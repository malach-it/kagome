use crate::{
    handlers::responses::cors_response, resources::crypto::SigningArtifact, unit::KagomeRequest,
};

use super::metadata::issuer_response;

pub fn handle_jwks(request: &KagomeRequest) -> String {
    cors_response(issuer_response(request, |_| {
        serde_json::json!({
            "keys": [
                SigningArtifact::Credential.public_jwk(),
                SigningArtifact::IdToken.public_jwk(),
                SigningArtifact::RequestObject.public_jwk()
            ]
        })
    }))
}
