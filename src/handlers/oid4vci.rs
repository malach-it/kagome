use crate::{
    errors::OAuthError,
    requests::{CredentialOfferRequest, CredentialRequest, IssuerRequest},
    resources::{
        credential_access_token, credential_issuer, pre_authorized_code, verifiable_credential,
    },
    unit::KagomeRequest,
};

use super::responses::{credential_error_response, logged_response, oid4vci_json_response};

pub fn credential_issuer_metadata(request: &KagomeRequest) -> String {
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

pub fn authorization_server_metadata(request: &KagomeRequest) -> String {
    issuer_response(request, |issuer| {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                pre_authorized_code::GRANT_TYPE
            ],
            "pre-authorized_grant_anonymous_access_supported": true
        })
    })
}

pub fn jwks(request: &KagomeRequest) -> String {
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

pub fn credential_offer(request: &KagomeRequest) -> String {
    match credential_issuer::validate(CredentialOfferRequest::from_request(request))
        .and_then(pre_authorized_code::generate)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => error.to_response(),
    }
}

pub fn credential(request: &KagomeRequest) -> String {
    match credential_issuer::validate(CredentialRequest::from_request(request))
        .and_then(credential_access_token::validate)
        .and_then(credential_issuer::validate_configuration)
        .and_then(verifiable_credential::generate)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => credential_error_response(&error),
    }
}

fn issuer_response(
    request: &KagomeRequest,
    body: impl FnOnce(&str) -> serde_json::Value,
) -> String {
    match credential_issuer::validate(IssuerRequest::from_request(request))
        .and_then(|request| metadata_response(request, body))
    {
        Ok(response) => response,
        Err(error) => error.to_response(),
    }
}

fn metadata_response(
    request: IssuerRequest<'_>,
    body: impl FnOnce(&str) -> serde_json::Value,
) -> Result<String, OAuthError> {
    Ok(oid4vci_json_response(
        &body(request.credential_issuer()?).to_string(),
    ))
}
