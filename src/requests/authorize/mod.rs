mod code;
mod login;

pub use code::{AuthorizeCodeRequest, AuthorizeCodeResponse};
pub use login::AuthorizeLoginRequest;

use crate::{
    resources::{resource_owner, response_type::ResponseType},
    unit::KagomeRequest,
};

pub(super) fn response_type_query(response_types: &[ResponseType]) -> Option<String> {
    if response_types.is_empty() {
        return None;
    }

    Some(
        response_types
            .iter()
            .map(|response_type| response_type.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

pub(super) fn valid_authorize_client_id(client_id: &str, request: &KagomeRequest) -> bool {
    let Some(host) = authorization_server_host(request) else {
        return false;
    };
    let Some((credentials, client_host)) = client_id.split_once('@') else {
        return false;
    };
    let (username, has_password) = credentials
        .split_once(':')
        .map_or((credentials, false), |(username, _)| (username, true));

    !username.is_empty()
        && client_host == host
        && (has_password || resource_owner::USERNAMES.contains(&username))
}

pub(super) fn client_id_username(client_id: Option<&str>) -> Option<&str> {
    let (credentials, _) = client_id?.split_once('@')?;
    let username = credentials
        .split_once(':')
        .map_or(credentials, |(username, _)| username);

    (!username.is_empty()).then_some(username)
}

fn authorization_server_host(request: &KagomeRequest) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value.as_str())
}
