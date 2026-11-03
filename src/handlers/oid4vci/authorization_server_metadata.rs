use crate::{
    resources::{pkce, pre_authorized_code, response_type},
    unit::KagomeRequest,
};

use super::metadata::issuer_response;

/// Handle `GET /.well-known/oauth-authorization-server`.
///
/// Validates the issuer and returns JSON describing authorization, token, and JWKS
/// endpoints, supported response and grant types, and PKCE support. Issuer errors
/// become OAuth error responses; configured CORS policy applies to both outcomes.
pub fn handle_authorization_server_metadata(request: &KagomeRequest) -> String {
    issuer_response(request, |issuer| {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code", response_type::PRE_AUTHORIZED_CODE],
            "grant_types_supported": [
                "authorization_code",
                pre_authorized_code::GRANT_TYPE
            ],
            "code_challenge_methods_supported": [pkce::CODE_CHALLENGE_METHOD],
            "pre-authorized_grant_anonymous_access_supported": true
        })
    })
}
