use crate::{resources::verifiable_credential, unit::KagomeRequest};

use super::metadata::issuer_response;

pub fn handle_jwks(request: &KagomeRequest) -> String {
    issuer_response(request, |_| {
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": verifiable_credential::SIGNING_ALGORITHM,
                "use": "sig",
                "kid": verifiable_credential::KEY_ID,
                "x": verifiable_credential::PUBLIC_KEY_X
            }]
        })
    })
}
