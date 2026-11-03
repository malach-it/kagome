use crate::{resources::crypto::SigningArtifact, unit::KagomeRequest};

use super::metadata::issuer_response;

/// Handle `GET /jwks` and `GET /openid/jwks`.
///
/// Validates the issuer and returns a JSON Web Key Set with public credential,
/// ID-token, and request-object signing keys. Issuer errors become OAuth error
/// responses; configured CORS policy applies to both outcomes.
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
