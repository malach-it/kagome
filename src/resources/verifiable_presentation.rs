use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header, get_current_timestamp,
};
use serde::Deserialize;
use serde_json::Value;

use crate::errors::OAuthError;

use super::{
    credential_issuer::CREDENTIAL_TYPE,
    presentation_state::PresentationStateClaims,
    verifiable_credential::{HOLDER_PUBLIC_KEY_X, PUBLIC_KEY},
};

#[derive(Debug)]
pub struct ValidatedPresentation {
    pub subject: String,
    pub credential_issuer: String,
}

#[derive(Debug, Deserialize)]
struct PresentationClaims {
    iss: String,
    aud: String,
    nonce: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    vp: PresentationBody,
}

#[derive(Debug, Deserialize)]
struct PresentationBody {
    #[serde(rename = "type")]
    presentation_types: Vec<String>,
    #[serde(rename = "verifiableCredential")]
    credentials: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CredentialClaims {
    iss: String,
    sub: String,
    iat: u64,
    exp: u64,
    cnf: Confirmation,
    vc: CredentialBody,
}

#[derive(Debug, Deserialize)]
struct Confirmation {
    jwk: Value,
}

#[derive(Debug, Deserialize)]
struct CredentialBody {
    #[serde(rename = "type")]
    credential_types: Vec<String>,
    #[serde(rename = "credentialSubject")]
    credential_subject: Value,
}

pub trait Validate {
    fn request_vp_token(&self) -> Option<&str>;
    fn presentation_state_claims(&self) -> Option<&PresentationStateClaims>;
    fn add_validated_presentation(&mut self, presentation: ValidatedPresentation);
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let vp_token = request
        .request_vp_token()
        .ok_or_else(|| invalid("vp_token is required"))?;
    let state = request
        .presentation_state_claims()
        .ok_or_else(|| invalid("state must be validated before vp_token"))?;
    let presentation_jwt = presentation_jwt(vp_token, &state.query_id)?;
    let header = decode_header(&presentation_jwt)
        .map_err(|_| invalid("vp_token presentation must be a jwt"))?;

    if header.alg != Algorithm::EdDSA {
        return Err(invalid("vp_token presentation algorithm must be EdDSA"));
    }

    let holder_jwk = header
        .jwk
        .ok_or_else(|| invalid("vp_token presentation header must include jwk"))?;
    validate_holder_jwk(&holder_jwk)?;
    let holder_key = DecodingKey::from_jwk(&holder_jwk)
        .map_err(|_| invalid("vp_token presentation jwk must be valid"))?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_required_spec_claims(&["exp", "nbf"]);
    validation.set_audience(&[state.client_id.as_str()]);
    let presentation = decode::<PresentationClaims>(&presentation_jwt, &holder_key, &validation)
        .map_err(|_| invalid("vp_token presentation is invalid or expired"))?
        .claims;

    validate_presentation_claims(&presentation, state)?;
    let credential = validate_credential(&presentation.vp.credentials[0], state)?;
    let presented_jwk = serde_json::to_value(&holder_jwk)
        .map_err(|_| invalid("vp_token presentation jwk must be valid"))?;

    if credential.cnf.jwk != presented_jwk {
        return Err(invalid(
            "vp_token presentation key must match the credential holder key",
        ));
    }

    if credential.sub != presentation.iss {
        return Err(invalid(
            "vp_token presentation holder must match the credential subject",
        ));
    }

    request.add_validated_presentation(ValidatedPresentation {
        subject: credential.sub,
        credential_issuer: credential.iss,
    });
    Ok(request)
}

fn presentation_jwt(vp_token: &str, query_id: &str) -> Result<String, OAuthError> {
    let vp_token: Value =
        serde_json::from_str(vp_token).map_err(|_| invalid("vp_token must be a JSON object"))?;
    let entries = vp_token
        .as_object()
        .ok_or_else(|| invalid("vp_token must be a JSON object"))?;

    if entries.len() != 1 {
        return Err(invalid(
            "vp_token must satisfy exactly one credential query",
        ));
    }

    let presentations = entries
        .get(query_id)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("vp_token does not satisfy the requested credential query"))?;

    if presentations.len() != 1 {
        return Err(invalid(
            "vp_token credential query must contain exactly one presentation",
        ));
    }

    presentations[0]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("vp_token presentation must be a string"))
}

fn validate_presentation_claims(
    presentation: &PresentationClaims,
    state: &PresentationStateClaims,
) -> Result<(), OAuthError> {
    let now = get_current_timestamp();

    if presentation.aud != state.client_id {
        return Err(invalid("vp_token presentation audience is invalid"));
    }
    if presentation.nonce != state.nonce {
        return Err(invalid("vp_token presentation nonce is invalid"));
    }
    if presentation.iat > now || presentation.nbf > now || presentation.exp <= presentation.iat {
        return Err(invalid("vp_token presentation time claims are invalid"));
    }
    if !presentation
        .vp
        .presentation_types
        .iter()
        .any(|presentation_type| presentation_type == "VerifiablePresentation")
    {
        return Err(invalid("vp_token must be a VerifiablePresentation"));
    }
    if presentation.vp.credentials.len() != 1 {
        return Err(invalid(
            "vp_token presentation must contain exactly one credential",
        ));
    }

    Ok(())
}

fn validate_credential(
    credential: &str,
    state: &PresentationStateClaims,
) -> Result<CredentialClaims, OAuthError> {
    let header =
        decode_header(credential).map_err(|_| invalid("presented credential must be a jwt"))?;
    if header.alg != Algorithm::EdDSA {
        return Err(invalid("presented credential algorithm must be EdDSA"));
    }

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_required_spec_claims(&["exp"]);
    validation.validate_aud = false;
    let credential = decode::<CredentialClaims>(
        credential,
        &DecodingKey::from_ed_pem(PUBLIC_KEY)
            .map_err(|_| invalid("credential issuer key is invalid"))?,
        &validation,
    )
    .map_err(|_| invalid("presented credential is invalid or expired"))?
    .claims;

    if credential.iss != state.credential_issuer {
        return Err(invalid("presented credential issuer is invalid"));
    }
    if credential.iat > get_current_timestamp() || credential.exp <= credential.iat {
        return Err(invalid("presented credential time claims are invalid"));
    }
    if !credential
        .vc
        .credential_types
        .iter()
        .any(|credential_type| credential_type == CREDENTIAL_TYPE)
    {
        return Err(invalid(
            "presented credential type does not satisfy the query",
        ));
    }
    if credential
        .vc
        .credential_subject
        .pointer("/degree")
        .is_none()
    {
        return Err(invalid(
            "presented credential claims do not satisfy the query",
        ));
    }

    Ok(credential)
}

fn validate_holder_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> Result<(), OAuthError> {
    let value = serde_json::to_value(jwk)
        .map_err(|_| invalid("vp_token presentation jwk must be valid"))?;
    if value.get("kty").and_then(Value::as_str) != Some("OKP")
        || value.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || value.get("x").and_then(Value::as_str) != Some(HOLDER_PUBLIC_KEY_X)
    {
        return Err(invalid("vp_token presentation holder key is not trusted"));
    }

    Ok(())
}

fn invalid(description: &str) -> OAuthError {
    OAuthError::invalid_request(description)
}
