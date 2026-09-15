use crate::{
    resources::{pre_authorized_code, response_type},
    unit::KagomeRequest,
};

use super::metadata::issuer_response;

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
            "pre-authorized_grant_anonymous_access_supported": true
        })
    })
}
