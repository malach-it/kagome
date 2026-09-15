use crate::{
    handlers::responses::cors_response,
    resources::{request_object, verifiable_credential},
    unit::KagomeRequest,
};

use super::metadata::issuer_response;

pub fn handle_jwks(request: &KagomeRequest) -> String {
    cors_response(issuer_response(request, |_| {
        serde_json::json!({
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": verifiable_credential::SIGNING_ALGORITHM,
                    "use": "sig",
                    "kid": verifiable_credential::KEY_ID,
                    "x": verifiable_credential::PUBLIC_KEY_X
                },
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "alg": request_object::SIGNING_ALGORITHM,
                    "use": "sig",
                    "kid": request_object::KEY_ID,
                    "x": request_object::PUBLIC_KEY_X,
                    "y": request_object::PUBLIC_KEY_Y
                }
            ]
        })
    }))
}
