use crate::{resources::crypto::SigningArtifact, unit::KagomeRequest};

use super::metadata::issuer_response;

pub fn handle_jwks(request: &KagomeRequest) -> String {
    issuer_response(request, |_| {
        serde_json::json!({
            "keys": [
                SigningArtifact::Credential.public_jwk(),
                SigningArtifact::IdToken.public_jwk(),
                SigningArtifact::RequestObject.public_jwk()
            ]
        })
    })
}
