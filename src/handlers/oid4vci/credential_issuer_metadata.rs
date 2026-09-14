use crate::{
    resources::{credential_issuer, verifiable_credential},
    unit::KagomeRequest,
};

use super::metadata::issuer_response;

pub fn handle_credential_issuer_metadata(request: &KagomeRequest) -> String {
    issuer_response(request, |issuer| {
        serde_json::json!({
            "credential_issuer": issuer,
            "credential_endpoint": format!("{issuer}/credential"),
            "credential_configurations_supported": {
                credential_issuer::CREDENTIAL_CONFIGURATION_ID: {
                    "format": credential_issuer::CREDENTIAL_FORMAT,
                    "scope": credential_issuer::CREDENTIAL_SCOPE,
                    "credential_signing_alg_values_supported": [
                        verifiable_credential::SIGNING_ALGORITHM
                    ],
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential",
                            credential_issuer::CREDENTIAL_TYPE
                        ]
                    },
                    "credential_metadata": {
                        "display": [{
                            "name": "University Degree Credential",
                            "locale": "en"
                        }],
                        "claims": [
                            {"path": ["credentialSubject", "id"], "mandatory": true},
                            {"path": ["credentialSubject", "degree"], "mandatory": true}
                        ]
                    }
                }
            }
        })
    })
}
