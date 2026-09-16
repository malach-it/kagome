use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    config::{Config, FederatedServerConfig},
    errors::OAuthError,
};

use super::{
    crypto::{self, CoseEncrypt0Errors, EncryptedArtifact},
    replay::{self, Artifact, ConsumeError},
    resource_owner::{self, ResourceOwner, ResourceOwnerAttributes},
};

const FEDERATION_STATE_TTL_SECONDS: u64 = 300;
const TOKEN_REQUEST_TIMEOUT_SECONDS: u64 = 10;
const INVALID_FEDERATION_STATE: &str = "federation callback state is invalid or expired";

#[derive(Debug)]
pub struct FederatedAuthorization {
    pub authorize_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FederationState {
    pub client_id: String,
    pub request_parameters: FederationRequestParameters,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationRequestParameters {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub authorization_code: Option<String>,
    pub metadata_policy: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct FederatedEndpointErrorResponse {
    error: Option<String>,
    error_description: Option<String>,
    message: Option<String>,
}

impl FederatedEndpointErrorResponse {
    fn message(self) -> Option<String> {
        [self.error_description, self.message, self.error]
            .into_iter()
            .flatten()
            .find(|message| !message.trim().is_empty())
    }
}

pub trait Authorize {
    fn validated_client_id(&self) -> Option<&str>;
    fn request_parameters(&self) -> FederationRequestParameters;
    fn add_federated_authorization(&mut self, authorization: FederatedAuthorization);
}

pub trait ValidateCallback {
    fn request_authorization_code(&self) -> Option<&str>;
    fn request_error(&self) -> Option<&str>;
    fn request_error_description(&self) -> Option<&str>;
    fn add_authorization_code(&mut self, authorization_code: String);
}

pub trait ValidateCallbackState {
    fn request_state(&self) -> Option<&str>;
    fn add_federation_state(&mut self, encoded_state: &str, state: FederationState);
}

pub trait ConsumeCallbackState {
    fn validated_federation_state(&self) -> Option<&str>;
    fn federation_state_expiration(&self) -> Option<u64>;
}

pub trait ExchangeToken {
    fn federation_authorization_code(&self) -> Option<&str>;
    fn federation_client_id(&self) -> Option<&str>;
    fn add_federated_access_token(&mut self, access_token: String);
}

pub trait FetchIdentity: resource_owner::Populate {
    fn federated_access_token(&self) -> Option<&str>;
    fn federation_client_id(&self) -> Option<&str>;
}

/// Starts upstream authentication using the validated downstream client's configuration.
///
/// Resolves the federated server assigned to the validated client, preserves the downstream
/// request in encrypted state, and adds the upstream authorization endpoint and parameters.
///
/// # Errors
///
/// Returns `invalid_token_response` when client or federation configuration is missing, or an
/// OAuth error when the state cannot be timestamped or encrypted.
pub fn authorize<T: Authorize>(request: T) -> Result<T, OAuthError> {
    let config = Config::global();
    let federated_server = configuration(&request).ok_or_else(|| {
        OAuthError::invalid_token_response("federated server configuration is required")
    })?;

    authorize_with_server(request, federated_server, &config.server.issuer)
}

/// Creates an upstream authorization redirect with encrypted original-request state.
///
/// Requires a validated downstream client ID. The generated five-minute state binds that client
/// to the original request and the configured callback URI; the resulting redirect parameters are
/// added to the request.
///
/// # Errors
///
/// Returns an OAuth error when the client ID is absent or state creation fails.
pub fn authorize_with_server<T: Authorize>(
    mut request: T,
    federated_server: &FederatedServerConfig,
    issuer: &str,
) -> Result<T, OAuthError> {
    let client_id = request
        .validated_client_id()
        .ok_or_else(|| OAuthError::invalid_token_response("federation client_id is required"))?
        .to_owned();
    let state = encode_state(
        &client_id,
        request.request_parameters(),
        current_timestamp()?,
    )?;

    request.add_federated_authorization(FederatedAuthorization {
        authorize_endpoint: federated_server.authorize_endpoint.clone(),
        client_id: federated_server.client_id.clone(),
        redirect_uri: callback_uri(issuer),
        state,
    });

    Ok(request)
}

/// Returns the federated-server configuration selected by the validated client ID.
///
/// Returns `None` when the request has no validated client or that client is not federation
/// enabled. This lookup does not mutate request state.
pub fn configuration<T: Authorize>(request: &T) -> Option<&'static FederatedServerConfig> {
    let client_id = request.validated_client_id()?;

    configured_federated_server(client_id)
}

/// Requires exactly one valid upstream authorization code or error response.
///
/// A non-empty code is copied into validated callback state. An upstream error is converted into
/// an OAuth grant failure and never stored.
///
/// # Errors
///
/// Returns `invalid_request` for missing, empty, or conflicting callback fields and
/// `invalid_grant` when the upstream server reports an error.
pub fn validate_callback<T: ValidateCallback>(mut request: T) -> Result<T, OAuthError> {
    match (
        request.request_authorization_code(),
        request.request_error(),
    ) {
        (Some(_), Some(_)) => Err(OAuthError::invalid_request(
            "federation callback must not include both code and error",
        )),
        (Some(""), None) => Err(OAuthError::invalid_request(
            "federation callback code must not be empty",
        )),
        (Some(authorization_code), None) => {
            let authorization_code = authorization_code.to_owned();
            request.add_authorization_code(authorization_code);
            Ok(request)
        }
        (None, Some("")) => Err(OAuthError::invalid_request(
            "federation callback error must not be empty",
        )),
        (None, Some(error)) => {
            let description = request.request_error_description().unwrap_or(error);
            Err(OAuthError::invalid_grant(format!(
                "federated server returned an error: {description}"
            )))
        }
        (None, None) => Err(OAuthError::invalid_request(
            "federation callback requires code or error",
        )),
    }
}

/// Validates the mutually exclusive upstream callback code/error shape without consuming state.
///
/// This action permits state consumption only for a syntactically complete callback. A supported
/// upstream error is considered a valid callback shape even though [`validate_callback`] later
/// converts it into an OAuth grant failure.
///
/// # Errors
///
/// Returns `invalid_request` for missing, empty, or conflicting callback fields.
pub fn validate_callback_shape<T: ValidateCallback>(request: T) -> Result<T, OAuthError> {
    match (
        request.request_authorization_code(),
        request.request_error(),
    ) {
        (Some(code), None) if !code.is_empty() => Ok(request),
        (None, Some(error)) if !error.is_empty() => Ok(request),
        (Some(_), Some(_)) => Err(OAuthError::invalid_request(
            "federation callback must not include both code and error",
        )),
        (Some(""), None) => Err(OAuthError::invalid_request(
            "federation callback code must not be empty",
        )),
        (None, Some("")) => Err(OAuthError::invalid_request(
            "federation callback error must not be empty",
        )),
        (None, None) => Err(OAuthError::invalid_request(
            "federation callback requires code or error",
        )),
        (Some(_), None) | (None, Some(_)) => unreachable!("empty values are handled above"),
    }
}

/// Authenticates callback state and revalidates its client and redirect destination.
///
/// Decrypts the state, requires its embedded client ID to agree with the preserved request, and
/// checks the preserved redirect URI against the client's current allowlist before adding the
/// state to the callback request.
///
/// # Errors
///
/// Returns `invalid_request` when state is missing, invalid, expired, refers to an unknown or
/// non-federated client, or contains an untrusted redirect destination.
pub fn validate_callback_state<T: ValidateCallbackState>(mut request: T) -> Result<T, OAuthError> {
    let encoded_state = request
        .request_state()
        .map(str::to_owned)
        .ok_or_else(|| OAuthError::invalid_request(INVALID_FEDERATION_STATE))?;
    let state = decrypt_state(&encoded_state)?;
    let client = Config::global()
        .client(&state.client_id)
        .ok_or_else(|| OAuthError::invalid_request(INVALID_FEDERATION_STATE))?;
    let parameters = &state.request_parameters;
    if parameters.client_id.as_deref() != Some(state.client_id.as_str())
        || !parameters
            .redirect_uri
            .as_ref()
            .is_some_and(|redirect_uri| {
                client
                    .redirect_uris
                    .iter()
                    .any(|configured| configured == redirect_uri)
            })
    {
        return Err(OAuthError::invalid_request(INVALID_FEDERATION_STATE));
    }

    request.add_federation_state(&encoded_state, state);
    Ok(request)
}

/// Atomically consumes validated federation callback state.
///
/// Call this after [`validate_callback_shape`] so malformed callbacks cannot invalidate an
/// outstanding upstream authorization request. The encrypted state remains recorded as a
/// domain-separated digest until its validated expiration.
///
/// # Errors
///
/// Returns `invalid_request` when state was already consumed and `invalid_token_response` when
/// validated state or replay storage is unavailable.
pub fn consume_callback_state<T: ConsumeCallbackState>(request: T) -> Result<T, OAuthError> {
    let state = request.validated_federation_state().ok_or_else(|| {
        OAuthError::invalid_token_response(
            "federation callback state must be validated before consumption",
        )
    })?;
    let expires_at = request.federation_state_expiration().ok_or_else(|| {
        OAuthError::invalid_token_response(
            "federation callback state expiration must be validated before consumption",
        )
    })?;

    replay::consume(Artifact::FederationState, state, expires_at).map_err(|error| match error {
        ConsumeError::AlreadyConsumed => {
            OAuthError::invalid_request("federation callback state has already been used")
        }
        ConsumeError::CapacityExceeded
        | ConsumeError::StorageUnavailable
        | ConsumeError::TimeUnavailable => {
            OAuthError::invalid_token_response("federation state replay storage failed")
        }
    })?;

    Ok(request)
}

/// Decrypts unexpired federation state for a client that remains federation-enabled.
///
/// This lower-level operation authenticates the artifact, validates its lifetime, and checks the
/// current federation configuration. It does not perform callback redirect-URI allowlist checks.
///
/// # Errors
///
/// Returns `invalid_request` for malformed, unauthenticated, expired, or no-longer-configured
/// federation state.
pub fn decrypt_state(encoded: &str) -> Result<FederationState, OAuthError> {
    let state = decode_state(encoded, current_timestamp()?)?;
    configured_federated_server(&state.client_id)
        .ok_or_else(|| OAuthError::invalid_request(INVALID_FEDERATION_STATE))?;

    Ok(state)
}

/// Exchanges the upstream code using the federated server selected by validated client state.
///
/// Resolves configuration from the validated federation client and adds the returned bearer token
/// to the request.
///
/// # Errors
///
/// Returns `invalid_token_response` when validated federation state or server configuration is
/// absent, and `invalid_grant` when the exchange fails or returns an invalid token response.
pub fn request_access_token<T: ExchangeToken>(request: T) -> Result<T, OAuthError> {
    let client_id = request.federation_client_id().ok_or_else(|| {
        OAuthError::invalid_token_response("validated federation state is required")
    })?;
    let server = configured_federated_server(client_id).ok_or_else(|| {
        OAuthError::invalid_token_response("federated server configuration is required")
    })?;

    request_access_token_with_server(request, server, &Config::global().server.issuer)
}

/// Exchanges the upstream code against an explicit token-endpoint configuration.
///
/// Sends the validated authorization code, configured client credentials, and this server's
/// callback URI to the upstream token endpoint, then stores its non-empty access token.
///
/// # Errors
///
/// Returns `invalid_token_response` when the code is absent and `invalid_grant` for transport,
/// decoding, or empty-token failures.
pub fn request_access_token_with_server<T: ExchangeToken>(
    mut request: T,
    server: &FederatedServerConfig,
    issuer: &str,
) -> Result<T, OAuthError> {
    let authorization_code = request.federation_authorization_code().ok_or_else(|| {
        OAuthError::invalid_token_response("federation authorization code is required")
    })?;
    let redirect_uri = callback_uri(issuer);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(TOKEN_REQUEST_TIMEOUT_SECONDS)))
        .build()
        .into();
    let mut response = agent
        .post(&server.token_endpoint)
        .send_form([
            ("grant_type", "authorization_code"),
            ("code", authorization_code),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", server.client_id.as_str()),
            ("client_secret", server.client_secret.as_str()),
        ])
        .map_err(|_| OAuthError::invalid_grant("federated token request failed"))?;
    let token: AccessTokenResponse = response
        .body_mut()
        .read_json()
        .map_err(|_| OAuthError::invalid_grant("federated token response is invalid"))?;

    if token.access_token.trim().is_empty() {
        return Err(OAuthError::invalid_grant(
            "federated token response is invalid",
        ));
    }

    request.add_federated_access_token(token.access_token);
    Ok(request)
}

/// Fetches identity using the federated server selected by validated client state.
///
/// Resolves configuration from the validated federation client and populates an authenticated
/// resource owner from all configured identity endpoints.
///
/// # Errors
///
/// Returns `invalid_token_response` when federation state or configuration is missing, and
/// `invalid_grant` when upstream identity retrieval or mapping fails.
pub fn fetch_identity<T: FetchIdentity>(request: T) -> Result<T, OAuthError> {
    let client_id = request.federation_client_id().ok_or_else(|| {
        OAuthError::invalid_token_response("validated federation state is required")
    })?;
    let server = configured_federated_server(client_id).ok_or_else(|| {
        OAuthError::invalid_token_response("federated server configuration is required")
    })?;

    fetch_identity_with_server(request, server)
}

/// Fetches configured upstream claims and populates an authenticated resource owner.
///
/// Requires a federated access token. Every configured endpoint and claim mapping must succeed;
/// mapped attributes retain their ID-token and credential exposure policies. The resulting
/// resource owner is marked authenticated and added to the request.
///
/// # Errors
///
/// Returns `invalid_token_response` when the access token is absent and `invalid_grant` for HTTP,
/// response, required-claim, or unusable-profile failures.
pub fn fetch_identity_with_server<T: FetchIdentity>(
    mut request: T,
    server: &FederatedServerConfig,
) -> Result<T, OAuthError> {
    let access_token = request
        .federated_access_token()
        .ok_or_else(|| OAuthError::invalid_token_response("federated access token is required"))?
        .to_owned();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(TOKEN_REQUEST_TIMEOUT_SECONDS)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut resource_owner_attributes = ResourceOwnerAttributes::default();

    for identity_endpoint in &server.endpoints {
        let mut response = agent
            .get(&identity_endpoint.endpoint)
            .header("authorization", format!("Bearer {access_token}"))
            .call()
            .map_err(|error| {
                OAuthError::invalid_grant(format!("federated identity request failed: {error}"))
            })?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response
                .body_mut()
                .read_json::<FederatedEndpointErrorResponse>()
                .ok()
                .and_then(FederatedEndpointErrorResponse::message)
                .unwrap_or_else(|| format!("HTTP {status}"));

            return Err(OAuthError::invalid_grant(format!(
                "federated identity request failed: {message}"
            )));
        }
        let identity: serde_json::Value = response
            .body_mut()
            .read_json()
            .map_err(|_| OAuthError::invalid_grant("federated identity response is invalid"))?;
        for identity_claim_config in &identity_endpoint.claims {
            let value = identity_claim(&identity, &identity_claim_config.claim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    OAuthError::invalid_grant("federated identity claim is missing or invalid")
                })?;

            resource_owner_attributes.add(
                &identity_claim_config.target,
                value.to_owned(),
                identity_claim_config.id_token,
                &identity_claim_config.credential,
            );
        }
    }

    let resource_owner =
        ResourceOwner::from_attributes(resource_owner_attributes).ok_or_else(|| {
            OAuthError::invalid_grant("federated identity profile must define username or sub")
        })?;
    request.add_resource_owner(resource_owner);

    Ok(request)
}

fn identity_claim<'a>(identity: &'a serde_json::Value, claim: &str) -> Option<&'a str> {
    claim
        .split('.')
        .try_fold(identity, |value, segment| value.get(segment))
        .and_then(serde_json::Value::as_str)
}

fn configured_federated_server(client_id: &str) -> Option<&'static FederatedServerConfig> {
    Config::global()
        .client(client_id)?
        .federated_server
        .as_ref()
}

fn callback_uri(issuer: &str) -> String {
    format!("{}/federation_callback", issuer.trim_end_matches('/'))
}

fn encode_state(
    client_id: &str,
    request_parameters: FederationRequestParameters,
    issued_at: u64,
) -> Result<String, OAuthError> {
    let state = FederationState {
        client_id: client_id.to_owned(),
        request_parameters,
        issued_at,
        expires_at: issued_at + FEDERATION_STATE_TTL_SECONDS,
    };
    let plaintext = serde_json::to_vec(&state)
        .map_err(|_| OAuthError::invalid_token_response("federation state generation failed"))?;

    crypto::encode_cose_encrypt0(&plaintext, EncryptedArtifact::FederationState)
}

fn decode_state(encoded: &str, now: u64) -> Result<FederationState, OAuthError> {
    let errors = CoseEncrypt0Errors {
        invalid_cose: INVALID_FEDERATION_STATE,
        missing_ciphertext: INVALID_FEDERATION_STATE,
        missing_nonce: INVALID_FEDERATION_STATE,
        decryption_failed: INVALID_FEDERATION_STATE,
    };
    let plaintext =
        crypto::decode_cose_encrypt0(encoded, EncryptedArtifact::FederationState, errors)
            .map_err(|_| OAuthError::invalid_request(INVALID_FEDERATION_STATE))?;
    let state: FederationState = serde_json::from_slice(&plaintext)
        .map_err(|_| OAuthError::invalid_request(INVALID_FEDERATION_STATE))?;

    if state.client_id.is_empty()
        || state.issued_at > now
        || state.expires_at < now
        || state.expires_at.saturating_sub(state.issued_at) != FEDERATION_STATE_TTL_SECONDS
    {
        return Err(OAuthError::invalid_request(INVALID_FEDERATION_STATE));
    }

    Ok(state)
}

fn current_timestamp() -> Result<u64, OAuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| OAuthError::invalid_token_response("system clock is before Unix epoch"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_expired_federation_state() {
        let now = 1_000;
        let state = encode_state(
            "client_id",
            request_parameters(),
            now - FEDERATION_STATE_TTL_SECONDS - 1,
        )
        .unwrap();

        let error = decode_state(&state, now).unwrap_err();

        assert_eq!(error.error, "invalid_request");
        assert_eq!(error.error_description, INVALID_FEDERATION_STATE);
    }

    #[test]
    fn rejects_tampered_federation_state() {
        let mut state = encode_state("client_id", request_parameters(), 1_000).unwrap();
        state.push('A');

        let error = decode_state(&state, 1_000).unwrap_err();

        assert_eq!(error.error, "invalid_request");
        assert_eq!(error.error_description, INVALID_FEDERATION_STATE);
    }

    #[test]
    fn encrypts_and_restores_parsed_request_parameters() {
        let parameters = request_parameters();
        let state = encode_state("client_id", request_parameters(), 1_000).unwrap();

        let decoded = decode_state(&state, 1_000).unwrap();

        assert_eq!(decoded.request_parameters, parameters);
    }

    #[test]
    fn resolves_nested_identity_claim() {
        let identity = serde_json::json!({"profile": {"username": "federated-user"}});

        assert_eq!(
            identity_claim(&identity, "profile.username"),
            Some("federated-user")
        );
    }

    fn request_parameters() -> FederationRequestParameters {
        FederationRequestParameters {
            response_type: Some("code token".to_owned()),
            client_id: Some("client_id".to_owned()),
            redirect_uri: Some("https://client.example.com/callback".to_owned()),
            state: Some("client state".to_owned()),
            authorization_code: Some("previous-code".to_owned()),
            metadata_policy: Some(r#"{"username":"username"}"#.to_owned()),
            scope: Some("openid profile".to_owned()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            username: Some("username".to_owned()),
            password: Some("password".to_owned()),
        }
    }
}
