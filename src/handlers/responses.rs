use crate::{
    errors::OAuthError,
    requests::{
        AuthorizationCodeRequest, AuthorizeCodeRequest, AuthorizeLoginRequest,
        ClientCredentialsRequest, CodeChainAuthorizationCodeRequest, CodeChainRequest,
    },
    resources::{
        access_token::AccessToken, authorization_code::AuthorizationCode, grant_type::GrantType,
        id_token::IdToken, ssh_keys::SshKeys,
    },
};
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

pub fn access_token_redirect_response(redirect_uri: &str, access_token: &AccessToken) -> String {
    let location = append_fragment_parameter(
        &append_fragment_parameter(
            redirect_uri,
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

pub fn ssh_keys_redirect_response(redirect_uri: &str, ssh_keys: &SshKeys) -> String {
    let location = append_fragment_parameter(
        &append_fragment_parameter(
            &append_fragment_parameter(
                redirect_uri,
                "ssh_private_key",
                &percent_encode_query_value(&ssh_keys.private_key),
            ),
            "ssh_public_key",
            &percent_encode_query_value(&ssh_keys.public_key),
        ),
        "ssh_certificate",
        &percent_encode_query_value(&ssh_keys.certificate),
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

pub fn login_page_response(request: &AuthorizeLoginRequest<'_>) -> String {
    let action = authorize_action(&request.request.query_params);
    let username_inputs = login_username_inputs(&request.request.query_params);
    let response_body = format!(
        "<!doctype html><html><head><title>kagome login</title></head><body><main><h1>kagome login</h1><form method=\"post\" action=\"{}\"><label>username {}</label><label>password <input name=\"password\" type=\"password\" autocomplete=\"current-password\"></label><button type=\"submit\">sign in</button></form></main></body></html>",
        escape_html(&action),
        username_inputs
    );

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

pub fn login_error_response(query_params: &[(String, String)], error: &OAuthError) -> String {
    if (error.format == "query" || query_parameter(query_params, "format") == Some("query"))
        && let Some(redirect_uri) = query_parameter(query_params, "redirect_uri")
    {
        return query_error_response(redirect_uri, error);
    }

    let action = authorize_action(query_params);
    let username_inputs = login_username_inputs(query_params);
    let response_body = format!(
        "<!doctype html><html><head><title>kagome login</title></head><body><main><h1>kagome login</h1><p role=\"alert\">{}</p><form method=\"post\" action=\"{}\"><label>username {}</label><label>password <input name=\"password\" type=\"password\" autocomplete=\"current-password\"></label><button type=\"submit\">sign in</button></form></main></body></html>",
        escape_html(&error.error_description),
        escape_html(&action),
        username_inputs
    );

    format!(
        "HTTP/1.1 400 Bad Request\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

fn login_username_inputs(query_params: &[(String, String)]) -> String {
    let Some(username) = query_parameter(query_params, "client_id").and_then(client_id_username)
    else {
        return "<input name=\"username\" autocomplete=\"username\">".to_owned();
    };
    let username = escape_html(username);

    format!(
        "<input name=\"username\" autocomplete=\"username\" value=\"{username}\" disabled><input type=\"hidden\" name=\"username\" value=\"{username}\">"
    )
}

fn client_id_username(client_id: &str) -> Option<&str> {
    let (credentials, _) = client_id.split_once('@')?;
    let username = credentials
        .split_once(':')
        .map_or(credentials, |(username, _)| username);

    (!username.is_empty()).then_some(username)
}

fn query_error_response(redirect_uri: &str, error: &OAuthError) -> String {
    let location = append_query_parameter(
        &append_query_parameter(
            redirect_uri,
            "error",
            &percent_encode_query_value(&error.error),
        ),
        "error_description",
        &percent_encode_query_value(&error.error_description),
    );

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
        log_authorize_success("login", &[("request.method", "GET".to_owned())]);
    }
}

impl ResponseLog for AuthorizeCodeRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        let authorization_code = self.response.authorization_code.as_ref();

        log_authorize_success(
            "code",
            &[
                (
                    "request.response_type",
                    optional_str(self.response_type.as_deref()),
                ),
                ("request.client_id", optional_str(self.client_id.as_deref())),
                (
                    "response.code",
                    optional_str(
                        authorization_code
                            .map(|authorization_code| authorization_code.value.as_str()),
                    ),
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
        let access_token = self.response.access_token.as_ref();

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
                    optional_str(access_token.map(|access_token| access_token.value.as_str())),
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
        let access_token = self.response.access_token.as_ref();

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
                    optional_str(access_token.map(|access_token| access_token.value.as_str())),
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
        let authorization_code = self.response.authorization_code.as_ref();

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
                    optional_str(
                        authorization_code
                            .map(|authorization_code| authorization_code.value.as_str()),
                    ),
                ),
            ],
        );
    }
}

impl ResponseLog for CodeChainAuthorizationCodeRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.to_response()
    }

    fn log_success(&self) {
        let access_token = self.response.access_token.as_ref();
        let authorization_code = self.response.authorization_code.as_ref();

        log_token_success(
            "code_chain_authorization_code",
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
                    "response.authorization_code",
                    optional_str(
                        authorization_code
                            .map(|authorization_code| authorization_code.value.as_str()),
                    ),
                ),
                (
                    "response.access_token",
                    optional_str(access_token.map(|access_token| access_token.value.as_str())),
                ),
            ],
        );
    }
}

fn log_token_success(response_type: &str, attributes: &[(&str, String)]) {
    eprintln!(
        "[{}] token_handler success type={} {}",
        log_timestamp(),
        response_type,
        attributes
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
}

fn log_authorize_success(response_type: &str, attributes: &[(&str, String)]) {
    eprintln!(
        "[{}] authorize_handler success type={} {}",
        log_timestamp(),
        response_type,
        attributes
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
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

fn redacted_optional(value: Option<&str>) -> String {
    if value.is_some() {
        "<redacted>".to_owned()
    } else {
        "<none>".to_owned()
    }
}

fn http_json_response(response_body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

fn append_query_parameter(uri: &str, name: &str, encoded_value: &str) -> String {
    let separator = if uri.contains('?') { '&' } else { '?' };

    format!("{uri}{separator}{name}={encoded_value}")
}

fn append_fragment_parameter(uri: &str, name: &str, encoded_value: &str) -> String {
    let separator = if uri.contains('#') { '&' } else { '#' };

    format!("{uri}{separator}{name}={encoded_value}")
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

fn query_parameter<'a>(query_params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    query_params
        .iter()
        .find(|(parameter_name, _)| parameter_name == name)
        .map(|(_, value)| value.as_str())
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

fn escape_html(value: &str) -> String {
    value.chars().fold(String::new(), |mut escaped, character| {
        match character {
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            character => escaped.push(character),
        }

        escaped
    })
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
