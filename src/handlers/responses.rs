use crate::{
    config::Config,
    errors::OAuthError,
    requests::{
        AuthorizationCodeRequest, AuthorizeCodeRequest, AuthorizeLoginRequest,
        ClientCredentialsRequest, CodeChainRequest, CredentialRequest, PreAuthorizedCodeRequest,
        PresentationResponseRequest, ResourceOwnerPasswordCredentialsRequest,
        SiopAuthorizationRequest, SiopResponseRequest,
    },
    resources::{
        access_token::AccessToken, authorization_code::AuthorizationCode, grant_type::GrantType,
        id_token::IdToken, pre_authorized_code, wallet_authorization,
    },
    templates,
};
use qrcode::{EcLevel, QrCode, render::svg};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub trait ResponseLog {
    fn to_http_response(&self) -> Result<String, OAuthError>;
    fn log_success(&self);
}

pub fn logged_response<T: ResponseLog>(response: T) -> Result<String, OAuthError> {
    let http_response = response.to_http_response()?;

    response.log_success();
    Ok(http_response)
}

pub fn cors_response(response: String) -> String {
    let Some((status_line, remainder)) = response.split_once("\r\n") else {
        return response;
    };

    format!("{status_line}\r\naccess-control-allow-origin: *\r\n{remainder}")
}

pub fn cors_preflight_response() -> String {
    "HTTP/1.1 204 No Content\r\naccess-control-allow-origin: *\r\naccess-control-allow-methods: POST, OPTIONS\r\naccess-control-allow-headers: content-type, authorization\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_owned()
}

pub fn log_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned())
}

pub fn access_token_response(access_token: &AccessToken) -> String {
    let response_body = format!(
        "{{\"token_type\":\"{}\",\"access_token\":\"{}\",\"expires_in\":{}}}",
        escape_json(&access_token.payload.token_type),
        escape_json(&access_token.value),
        access_token.expires_in
    );

    http_json_response(&response_body)
}

pub fn authorization_code_response(authorization_code: &AuthorizationCode) -> String {
    let response_body = format!(
        "{{\"authorization_code\":\"{}\",\"expires_in\":{}}}",
        escape_json(&authorization_code.value),
        authorization_code.expires_in
    );

    http_json_response(&response_body)
}

pub fn oid4vci_json_response(response_body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

pub fn credential_error_response(error: &OAuthError) -> String {
    let response_body = serde_json::json!({
        "error": error.error,
        "error_description": error.error_description,
    })
    .to_string();

    if error.kind == crate::errors::OAuthErrorCode::InvalidAccessToken {
        return format!(
            "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncache-control: no-store\r\nwww-authenticate: Bearer error=\"invalid_token\"\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
    }

    format!(
        "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

pub fn oid4vp_json_response(response_body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

pub fn oid4vp_error_response(error: &OAuthError) -> String {
    let response_body = serde_json::json!({
        "error": error.error,
        "error_description": error.error_description,
    })
    .to_string();

    format!(
        "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

pub fn authorization_request_redirect_response(
    redirect_uri: &str,
    parameters: &[(&str, &str)],
) -> String {
    redirect_response(&authorization_request_uri(redirect_uri, parameters))
}

pub fn authorization_request_uri(redirect_uri: &str, parameters: &[(&str, &str)]) -> String {
    let (base_uri, fragment) = redirect_uri
        .split_once('#')
        .map_or((redirect_uri, None), |(base, fragment)| {
            (base, Some(fragment))
        });
    let location = parameters
        .iter()
        .fold(base_uri.to_owned(), |uri, (name, value)| {
            append_query_parameter(&uri, name, &percent_encode_query_value(value))
        });
    match fragment {
        Some(fragment) => format!("{location}#{fragment}"),
        None => location,
    }
}

pub fn wallet_authorization_response(
    client_id: &str,
    authorization_uri: &str,
) -> Result<String, OAuthError> {
    if Config::global()
        .client(client_id)
        .is_some_and(|client| client.qr_code)
    {
        return qr_code_response(client_id, authorization_uri);
    }

    Ok(redirect_response(authorization_uri))
}

fn redirect_response(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncache-control: no-store\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
}

pub fn wallet_authorization_redirect_response(location: &str) -> String {
    redirect_response(location)
}

fn qr_code_response(client_id: &str, authorization_uri: &str) -> Result<String, OAuthError> {
    let relay = wallet_authorization::store(authorization_uri)?;
    let qr_code =
        QrCode::with_error_correction_level(relay.uri.as_bytes(), EcLevel::M).map_err(|_| {
            OAuthError::invalid_token_response(
                "wallet authorization relay is too large for a QR code",
            )
        })?;
    let svg = qr_code
        .render::<svg::Color>()
        .min_dimensions(320, 320)
        .build();
    let response_body = templates::wallet_authorization(
        client_id,
        authorization_uri,
        &relay.uri,
        &svg,
        &relay.identifier,
    )
    .map_err(|error| {
        OAuthError::invalid_token_response(format!(
            "wallet authorization page could not be rendered: {error}"
        ))
    })?;

    Ok(format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncache-control: no-store\r\ncontent-security-policy: default-src 'none'; script-src 'nonce-{}'; style-src 'nonce-{}'; img-src data:; base-uri 'none'; frame-ancestors 'none'\r\nreferrer-policy: no-referrer\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        relay.identifier,
        relay.identifier,
        response_body.len(),
        response_body
    ))
}

pub fn siopv2_error_redirect_response(
    redirect_uri: &str,
    error: &str,
    error_description: Option<&str>,
    state: Option<&str>,
) -> String {
    authorization_error_redirect_response(redirect_uri, error, error_description, state)
}

pub fn authorization_error_redirect_response(
    redirect_uri: &str,
    error: &str,
    error_description: Option<&str>,
    state: Option<&str>,
) -> String {
    let mut parameters = vec![("error", error)];
    if let Some(error_description) = error_description {
        parameters.push(("error_description", error_description));
    }
    if let Some(state) = state {
        parameters.push(("state", state));
    }

    authorization_request_redirect_response(redirect_uri, &parameters)
}

pub fn oauth_error_html_response(
    client_id: Option<&str>,
    error: &str,
    error_description: Option<&str>,
) -> String {
    let description = error_description.unwrap_or(error);
    let response_body = templates::authorization_error(client_id, error, description)
        .expect("bundled authorization error template must render");

    format!(
        "HTTP/1.1 400 Bad Request\r\ncontent-type: text/html\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

pub fn code_redirect_response(
    redirect_uri: &str,
    authorization_code: &AuthorizationCode,
) -> String {
    let location = append_query_parameter(
        redirect_uri,
        "code",
        &percent_encode_query_value(&authorization_code.value),
    );

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

pub fn credential_offer_uri(
    redirect_uri: &str,
    credential_issuer: &str,
    pre_authorized_code: &str,
) -> String {
    let credential_offer = serde_json::json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": crate::config::Config::global()
            .credentials
            .iter()
            .map(|credential| credential.credential_configuration_id.as_str())
            .collect::<Vec<_>>(),
        "grants": {
            pre_authorized_code::GRANT_TYPE: {
                "pre-authorized_code": pre_authorized_code
            }
        }
    })
    .to_string();
    append_query_parameter(
        redirect_uri,
        "credential_offer",
        &percent_encode_query_value(&credential_offer),
    )
}

pub fn federated_authorize_redirect_response(
    authorize_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
) -> String {
    let location = append_query_parameter(authorize_endpoint, "response_type", "code");
    let location = append_query_parameter(
        &location,
        "client_id",
        &percent_encode_query_value(client_id),
    );
    let location = append_query_parameter(
        &location,
        "redirect_uri",
        &percent_encode_query_value(redirect_uri),
    );
    let location = append_query_parameter(&location, "state", &percent_encode_query_value(state));

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

pub fn access_token_redirect_response(
    redirect_uri: &str,
    access_token: &AccessToken,
    state: Option<&str>,
) -> String {
    let location = append_fragment_parameter(
        &append_fragment_parameter(
            &append_fragment_parameter(
                redirect_uri,
                "access_token",
                &percent_encode_query_value(&access_token.value),
            ),
            "token_type",
            &percent_encode_query_value(&access_token.payload.token_type),
        ),
        "expires_in",
        &access_token.expires_in.to_string(),
    );
    let location = append_optional_fragment_parameter(&location, "state", state);

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

pub fn id_token_redirect_response(redirect_uri: &str, id_token: &IdToken) -> String {
    let location = append_fragment_parameter(
        &append_fragment_parameter(
            redirect_uri,
            "id_token",
            &percent_encode_query_value(&id_token.value),
        ),
        "expires_in",
        &id_token.expires_in.to_string(),
    );

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

pub fn id_token_access_token_redirect_response(
    redirect_uri: &str,
    id_token: &IdToken,
    access_token: &AccessToken,
) -> String {
    let location = append_fragment_parameter(
        &append_fragment_parameter(
            &append_fragment_parameter(
                redirect_uri,
                "id_token",
                &percent_encode_query_value(&id_token.value),
            ),
            "access_token",
            &percent_encode_query_value(&access_token.value),
        ),
        "expires_in",
        &access_token.expires_in.to_string(),
    );

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

pub fn code_access_token_redirect_response(
    redirect_uri: &str,
    authorization_code: &AuthorizationCode,
    access_token: &AccessToken,
) -> String {
    let location = append_fragment_parameter(
        &append_fragment_parameter(
            &append_query_parameter(
                redirect_uri,
                "code",
                &percent_encode_query_value(&authorization_code.value),
            ),
            "access_token",
            &percent_encode_query_value(&access_token.value),
        ),
        "expires_in",
        &access_token.expires_in.to_string(),
    );

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

pub fn code_id_token_redirect_response(
    redirect_uri: &str,
    authorization_code: &AuthorizationCode,
    id_token: &IdToken,
) -> String {
    let location = append_fragment_parameter(
        &append_fragment_parameter(
            &append_query_parameter(
                redirect_uri,
                "code",
                &percent_encode_query_value(&authorization_code.value),
            ),
            "id_token",
            &percent_encode_query_value(&id_token.value),
        ),
        "expires_in",
        &id_token.expires_in.to_string(),
    );

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

pub fn code_id_token_access_token_redirect_response(
    redirect_uri: &str,
    authorization_code: &AuthorizationCode,
    id_token: &IdToken,
    access_token: &AccessToken,
) -> String {
    let location = append_fragment_parameter(
        &append_fragment_parameter(
            &append_fragment_parameter(
                &append_query_parameter(
                    redirect_uri,
                    "code",
                    &percent_encode_query_value(&authorization_code.value),
                ),
                "access_token",
                &percent_encode_query_value(&access_token.value),
            ),
            "id_token",
            &percent_encode_query_value(&id_token.value),
        ),
        "expires_in",
        &access_token.expires_in.to_string(),
    );

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

pub fn authorize_redirect_response(
    query_params: &[(String, String)],
    response_type: &str,
    authorization_code: &AuthorizationCode,
) -> String {
    let mut query_params = query_params.to_vec();
    set_query_parameter(&mut query_params, "response_type", response_type);
    set_query_parameter(&mut query_params, "code", &authorization_code.value);
    let location = authorize_action(&query_params);

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

pub fn not_implemented_response() -> String {
    let response_body = "not implemented";

    format!(
        "HTTP/1.1 501 Not Implemented\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

pub fn query_error_response(redirect_uri: &str, error: &OAuthError, state: Option<&str>) -> String {
    let location = append_query_parameter(
        &append_query_parameter(
            redirect_uri,
            "error",
            &percent_encode_query_value(&error.error),
        ),
        "error_description",
        &percent_encode_query_value(&error.error_description),
    );
    let location = append_optional_query_parameter(&location, "state", state);

    format!(
        "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        location
    )
}

impl ResponseLog for AuthorizeLoginRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        let flow = if self.response.pre_authorized_code.is_some() {
            "pre_authorized_code"
        } else if self.response.presentation_state.is_some() {
            "openid4vp"
        } else if self.response.siop_authenticated {
            "siopv2"
        } else if self.response.federated_authorization.is_some() {
            "federated_redirect"
        } else if self.response.federated_access_token.is_some() {
            "federation_callback"
        } else if self.response.authorization_code.is_some()
            || self.response.id_token.is_some()
            || self.response.access_token.is_some()
        {
            "authorization"
        } else {
            "not_implemented"
        };

        log_authorize_success(
            flow,
            &[
                ("request.method", "GET".to_owned()),
                (
                    "request.response_type",
                    optional_str(self.response_type.as_deref()),
                ),
                (
                    "request.client_id",
                    optional_str(self.response.client_id.as_deref()),
                ),
                (
                    "response.code",
                    artifact_status(self.response.authorization_code.as_ref()),
                ),
                (
                    "response.id_token",
                    artifact_status(self.response.id_token.as_ref()),
                ),
                (
                    "response.access_token",
                    artifact_status(self.response.access_token.as_ref()),
                ),
            ],
        );
    }
}

impl ResponseLog for AuthorizeCodeRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        let flow = if self.response.pre_authorized_code.is_some() {
            "pre_authorized_code"
        } else {
            "code"
        };

        log_authorize_success(
            flow,
            &[
                (
                    "request.response_type",
                    optional_str(self.response_type.as_deref()),
                ),
                ("request.client_id", optional_str(self.client_id.as_deref())),
                (
                    "response.code",
                    artifact_status(self.response.authorization_code.as_ref()),
                ),
            ],
        );
    }
}

impl ResponseLog for AuthorizationCodeRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        log_token_success(
            "authorization_code",
            &[
                (
                    "request.grant_type",
                    optional_str(self.grant_type.as_deref()),
                ),
                ("request.client_id", optional_str(self.client_id.as_deref())),
                (
                    "request.client_secret",
                    redacted_optional(self.client_secret.as_deref()),
                ),
                ("request.code", redacted_optional(self.code.as_deref())),
                (
                    "response.access_token",
                    artifact_status(self.response.access_token.as_ref()),
                ),
            ],
        );
    }
}

impl ResponseLog for ClientCredentialsRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        log_token_success(
            "client_credentials",
            &[
                (
                    "request.grant_type",
                    optional_str(self.grant_type.as_deref()),
                ),
                ("request.client_id", optional_str(self.client_id.as_deref())),
                (
                    "request.client_secret",
                    redacted_optional(self.client_secret.as_deref()),
                ),
                (
                    "response.access_token",
                    artifact_status(self.response.access_token.as_ref()),
                ),
            ],
        );
    }
}

impl ResponseLog for ResourceOwnerPasswordCredentialsRequest {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        log_token_success(
            "password",
            &[
                (
                    "request.grant_type",
                    optional_str(self.grant_type.as_deref()),
                ),
                ("request.client_id", optional_str(self.client_id.as_deref())),
                (
                    "request.client_secret",
                    redacted_optional(self.client_secret.as_deref()),
                ),
                ("request.username", optional_str(self.username.as_deref())),
                (
                    "request.password",
                    redacted_optional(self.password.as_deref()),
                ),
                (
                    "response.access_token",
                    artifact_status(self.response.access_token.as_ref()),
                ),
            ],
        );
    }
}

impl ResponseLog for CodeChainRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        log_token_success(
            "code_chain",
            &[
                (
                    "request.grant_type",
                    grant_type_value(self.response.grant_type),
                ),
                ("request.client_id", optional_str(self.client_id.as_deref())),
                (
                    "request.client_secret",
                    redacted_optional(self.client_secret.as_deref()),
                ),
                (
                    "request.authorization_code",
                    redacted_optional(self.authorization_code.as_deref()),
                ),
                (
                    "request.id_token",
                    redacted_optional(self.response.id_token.as_deref()),
                ),
                (
                    "response.authorization_code",
                    artifact_status(self.response.authorization_code.as_ref()),
                ),
            ],
        );
    }
}

impl ResponseLog for PreAuthorizedCodeRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        log_token_success(
            "pre_authorized_code",
            &[("request.pre-authorized_code", "<redacted>".to_owned())],
        );
    }
}

impl ResponseLog for CredentialRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        eprintln!(
            "[{}] credential_handler success configuration={}",
            log_timestamp(),
            optional_str(
                self.response
                    .credential_configuration
                    .as_ref()
                    .map(|credential| credential.credential_configuration_id.as_str())
            )
        );
    }
}

impl ResponseLog for PresentationResponseRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        eprintln!(
            "[{}] presentation_response_handler success outcome={}",
            log_timestamp(),
            if self.response.wallet_error.is_some() {
                "wallet_error"
            } else {
                "presentation"
            }
        );
    }
}

impl ResponseLog for SiopAuthorizationRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        eprintln!(
            "[{}] siopv2_request_handler success response_mode=direct_post",
            log_timestamp()
        );
    }
}

impl ResponseLog for SiopResponseRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        eprintln!(
            "[{}] siopv2_response_handler success outcome={}",
            log_timestamp(),
            if self.response.wallet_error.is_some() {
                "wallet_error"
            } else {
                "id_token"
            }
        );
    }
}

fn log_token_success(response_type: &str, attributes: &[(&str, String)]) {
    eprintln!("{}", token_success_log(response_type, attributes));
}

fn log_authorize_success(response_type: &str, attributes: &[(&str, String)]) {
    eprintln!("{}", authorize_success_log(response_type, attributes));
}

fn token_success_log(response_type: &str, attributes: &[(&str, String)]) -> String {
    format!(
        "[{}] token_handler success type={} {}",
        log_timestamp(),
        response_type,
        log_attributes(attributes)
    )
}

fn authorize_success_log(response_type: &str, attributes: &[(&str, String)]) -> String {
    format!(
        "[{}] authorize_handler success type={} {}",
        log_timestamp(),
        response_type,
        log_attributes(attributes)
    )
}

fn log_attributes(attributes: &[(&str, String)]) -> String {
    attributes
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn grant_type_value(grant_type: Option<GrantType>) -> String {
    grant_type
        .map(GrantType::as_str)
        .unwrap_or("<none>")
        .to_owned()
}

fn optional_str(value: Option<&str>) -> String {
    value.unwrap_or("<none>").to_owned()
}

fn artifact_status<T: ?Sized>(artifact: Option<&T>) -> String {
    if artifact.is_some() {
        "issued".to_owned()
    } else {
        "<none>".to_owned()
    }
}

fn redacted_optional(value: Option<&str>) -> String {
    if value.is_some() {
        "<redacted>".to_owned()
    } else {
        "<none>".to_owned()
    }
}

fn http_json_response(response_body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\npragma: no-cache\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

fn append_query_parameter(uri: &str, name: &str, encoded_value: &str) -> String {
    let separator = if uri.contains('?') { '&' } else { '?' };

    format!("{uri}{separator}{name}={encoded_value}")
}

fn append_optional_query_parameter(uri: &str, name: &str, value: Option<&str>) -> String {
    value.map_or_else(
        || uri.to_owned(),
        |value| append_query_parameter(uri, name, &percent_encode_query_value(value)),
    )
}

fn append_fragment_parameter(uri: &str, name: &str, encoded_value: &str) -> String {
    let separator = if uri.contains('#') { '&' } else { '#' };

    format!("{uri}{separator}{name}={encoded_value}")
}

fn append_optional_fragment_parameter(uri: &str, name: &str, value: Option<&str>) -> String {
    value.map_or_else(
        || uri.to_owned(),
        |value| append_fragment_parameter(uri, name, &percent_encode_query_value(value)),
    )
}

fn authorize_action(query_params: &[(String, String)]) -> String {
    if query_params.is_empty() {
        return "/authorize".to_owned();
    }

    let query = query_params
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                percent_encode_query_value(name),
                percent_encode_query_value(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&");

    format!("/authorize?{query}")
}

fn set_query_parameter(query_params: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some((_, existing_value)) = query_params
        .iter_mut()
        .find(|(existing_name, _)| existing_name == name)
    {
        *existing_value = value.to_owned();
    } else {
        query_params.push((name.to_owned(), value.to_owned()));
    }
}

fn percent_encode_query_value(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            byte => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn escape_json(value: &str) -> String {
    value.chars().fold(String::new(), |mut escaped, character| {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }

        escaped
    })
}

#[cfg(test)]
mod tests {
    use super::{artifact_status, authorize_success_log, token_success_log};

    #[test]
    fn successful_log_lines_exclude_bearer_artifacts() {
        let authorization_code = "g0OhAQOhBUx-recognizable-authorization-code";
        let access_token = "g0OhAQOhBUx-recognizable-access-token";
        let authorize_log = authorize_success_log(
            "code",
            &[("response.code", artifact_status(Some(authorization_code)))],
        );
        let token_log = token_success_log(
            "authorization_code",
            &[("response.access_token", artifact_status(Some(access_token)))],
        );

        assert!(!authorize_log.contains(authorization_code));
        assert!(!token_log.contains(access_token));
        assert!(authorize_log.contains("response.code=issued"));
        assert!(token_log.contains("response.access_token=issued"));
    }

    #[test]
    fn successful_log_lines_preserve_missing_artifact_status() {
        let log = authorize_success_log(
            "pre_authorized_code",
            &[("response.code", artifact_status::<str>(None))],
        );

        assert!(log.contains("response.code=<none>"));
    }
}
