use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    config::{Config, FederatedServerConfig},
    errors::OAuthError,
};

use super::crypto::{self, CoseEncrypt0Errors};

const FEDERATION_STATE_SECRET: &str = "static_federation_state_secret";
const FEDERATION_STATE_EXTERNAL_AAD: &[u8] = b"kagome.federation_state";
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
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: String,
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

pub trait ExchangeToken {
    fn federation_authorization_code(&self) -> Option<&str>;
    fn federation_client_id(&self) -> Option<&str>;
    fn add_federated_access_token(&mut self, access_token: String);
}

pub fn authorize<T: Authorize>(request: T) -> Result<T, OAuthError> {
    let config = Config::global();
    let federated_server = configuration(&request).ok_or_else(|| {
        OAuthError::invalid_token_response("federated server configuration is required")
    })?;

    authorize_with_server(request, federated_server, &config.server.issuer)
}

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

pub fn configuration<T: Authorize>(request: &T) -> Option<&'static FederatedServerConfig> {
    let client_id = request.validated_client_id()?;

    configured_federated_server(client_id)
}

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

pub fn decrypt_state(encoded: &str) -> Result<FederationState, OAuthError> {
    let state = decode_state(encoded, current_timestamp()?)?;
    configured_federated_server(&state.client_id)
        .ok_or_else(|| OAuthError::invalid_request(INVALID_FEDERATION_STATE))?;

    Ok(state)
}

pub fn request_access_token<T: ExchangeToken>(request: T) -> Result<T, OAuthError> {
    let client_id = request.federation_client_id().ok_or_else(|| {
        OAuthError::invalid_token_response("validated federation state is required")
    })?;
    let server = configured_federated_server(client_id).ok_or_else(|| {
        OAuthError::invalid_token_response("federated server configuration is required")
    })?;

    request_access_token_with_server(request, server, &Config::global().server.issuer)
}

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

fn configured_federated_server(client_id: &str) -> Option<&'static FederatedServerConfig> {
    Config::global()
        .clients
        .iter()
        .find(|client| client.client_id == client_id)?
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

    crypto::encode_cose_encrypt0(
        &plaintext,
        FEDERATION_STATE_SECRET,
        FEDERATION_STATE_EXTERNAL_AAD,
    )
}

fn decode_state(encoded: &str, now: u64) -> Result<FederationState, OAuthError> {
    let errors = CoseEncrypt0Errors {
        invalid_cose: INVALID_FEDERATION_STATE,
        missing_ciphertext: INVALID_FEDERATION_STATE,
        missing_nonce: INVALID_FEDERATION_STATE,
        decryption_failed: INVALID_FEDERATION_STATE,
    };
    let plaintext = crypto::decode_cose_encrypt0(
        encoded,
        FEDERATION_STATE_SECRET,
        FEDERATION_STATE_EXTERNAL_AAD,
        errors,
    )
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

    fn request_parameters() -> FederationRequestParameters {
        FederationRequestParameters {
            response_type: Some("code token".to_owned()),
            client_id: Some("client_id".to_owned()),
            redirect_uri: Some("https://client.example.com/callback".to_owned()),
            state: Some("client state".to_owned()),
            authorization_code: Some("previous-code".to_owned()),
            metadata_policy: Some(r#"{"username":"username"}"#.to_owned()),
            username: Some("username".to_owned()),
            password: Some("password".to_owned()),
        }
    }
}
