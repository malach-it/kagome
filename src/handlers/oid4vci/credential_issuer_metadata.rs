use serde_json::{Map, json};

use crate::{config::Config, resources::credential_issuer, unit::KagomeRequest};

use super::metadata::issuer_response;

pub fn handle_credential_issuer_metadata(request: &KagomeRequest) -> String {
    issuer_response(request, |issuer| {
        let configurations: Map<String, serde_json::Value> = Config::global()
            .credentials
            .iter()
            .map(|credential| {
                let credential_types: Vec<_> = std::iter::once("VerifiableCredential")
                    .chain(credential.credential_types.iter().map(String::as_str))
                    .collect();
                (credential.credential_configuration_id.clone(), json!({
                    "format": credential_issuer::CREDENTIAL_FORMAT,
                    "scope": credential.credential_configuration_id,
                    "vct": credential.vct,
                    "credential_signing_alg_values_supported": [
                        crate::resources::crypto::SigningArtifact::Credential.algorithm_name()
                    ],
                    "proof_types_supported": {
                        "jwt": {
                            "proof_signing_alg_values_supported":
                                crate::resources::verifiable_presentation::SUPPORTED_ALGORITHM_NAMES
                        }
                    },
                    "credential_definition": {
                        "type": credential_types
                    },
                    "display": [{"name": credential.name, "locale": "en"}],
                    "credential_metadata": {
                        "display": [{"name": credential.name, "locale": "en"}],
                        "claims": [
                            {"path": ["credentialSubject", "id"], "mandatory": true}
                        ]
                    }
                }))
            })
            .collect();
        json!({
            "credential_issuer": issuer,
            "credential_endpoint": format!("{issuer}/credential"),
            "credential_configurations_supported": configurations
        })
    })
}
