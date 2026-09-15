use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, Validation, decode, decode_header,
    get_current_timestamp,
};
use serde::Deserialize;
use serde_json::Value;

use crate::errors::OAuthError;

use super::{
    credential_issuer::CREDENTIAL_TYPE, presentation_state::PresentationStateClaims,
    self_issued_id_token, verifiable_credential::PUBLIC_KEY,
};

pub const SUPPORTED_ALGORITHM_NAMES: [&str; 9] = [
    "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA",
];

#[derive(Debug)]
pub struct ValidatedPresentation {
    pub subject: String,
    pub credential_issuer: String,
}

#[derive(Debug, Deserialize)]
struct PresentationClaims {
    iss: String,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    aud: Option<String>,
    nonce: String,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    vp: Option<PresentationBody>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "type")]
    presentation_types: Vec<String>,
    #[serde(default, rename = "verifiableCredential")]
    credentials: Vec<String>,
}

#[derive(Deserialize)]
struct PresentationIssuer {
    iss: String,
}

#[derive(Debug, Default, Deserialize)]
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
    vc: CredentialBody,
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
    fn presentation_submission_validated(&self) -> bool;
    fn add_validated_presentation(&mut self, presentation: ValidatedPresentation);
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let vp_token = request
        .request_vp_token()
        .ok_or_else(|| invalid("vp_token is required"))?;
    let state = request
        .presentation_state_claims()
        .ok_or_else(|| invalid("state must be validated before vp_token"))?;
    if !request.presentation_submission_validated() {
        return Err(invalid(
            "presentation_submission must be validated before vp_token",
        ));
    }
    let presentation_jwt = vp_token.to_owned();
    let header = decode_header(&presentation_jwt)
        .map_err(|_| invalid("vp_token presentation must be a jwt"))?;

    if header.alg.family() == AlgorithmFamily::Hmac {
        return Err(invalid(
            "vp_token presentation algorithm must be asymmetric",
        ));
    }

    let holder_jwk = resolve_holder_jwk(&presentation_jwt, header.jwk, header.kid.as_deref())?;
    let holder_key = DecodingKey::from_jwk(&holder_jwk)
        .map_err(|_| invalid("vp_token presentation jwk must be valid"))?;
    let mut validation = Validation::new(header.alg);
    validation.required_spec_claims.clear();
    validation.validate_nbf = true;
    validation.validate_aud = false;
    let presentation = decode::<PresentationClaims>(&presentation_jwt, &holder_key, &validation)
        .map_err(|_| invalid("vp_token presentation is invalid or expired"))?
        .claims;
    if let Some(id_token_jwk) = state.id_token_public_jwk.as_ref() {
        let id_token_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(id_token_jwk.clone())
            .map_err(|_| invalid("id_token public key is invalid"))?;
        let id_token_key = DecodingKey::from_jwk(&id_token_jwk)
            .map_err(|_| invalid("id_token public key is invalid"))?;
        decode::<PresentationClaims>(&presentation_jwt, &id_token_key, &validation).map_err(
            |_| invalid("vp_token presentation signature does not match id_token public key"),
        )?;
    }

    let credentials = validate_presentation_claims(&presentation, state)?;
    let credential = validate_credential(&credentials[0], state)?;

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

fn resolve_holder_jwk(
    token: &str,
    header_jwk: Option<jsonwebtoken::jwk::Jwk>,
    key_id: Option<&str>,
) -> Result<jsonwebtoken::jwk::Jwk, OAuthError> {
    if let Some(jwk) = header_jwk {
        return Ok(jwk);
    }

    let key_id = key_id
        .ok_or_else(|| invalid("vp_token presentation header must include jwk or a did:key kid"))?;
    let issuer = decode_unverified_issuer(token)?;
    if !issuer.iss.starts_with("did:key:")
        || !(key_id == issuer.iss
            || key_id
                .strip_prefix(&issuer.iss)
                .is_some_and(|fragment| fragment.starts_with('#')))
    {
        return Err(invalid(
            "vp_token presentation kid must identify the issuer did:key",
        ));
    }
    let jwk = self_issued_id_token::did_key_jwk(&issuer.iss)
        .map_err(|_| invalid("vp_token presentation kid must contain a valid P-256 did:key"))?;

    serde_json::from_value(jwk)
        .map_err(|_| invalid("vp_token presentation kid must contain a valid P-256 did:key"))
}

fn decode_unverified_issuer(token: &str) -> Result<PresentationIssuer, OAuthError> {
    let mut segments = token.split('.');
    let _header = segments.next();
    let payload = segments
        .next()
        .ok_or_else(|| invalid("vp_token presentation must be a jwt"))?;
    if segments.next().is_none() || segments.next().is_some() {
        return Err(invalid("vp_token presentation must be a jwt"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid("vp_token presentation claims are invalid"))?;

    serde_json::from_slice(&payload)
        .map_err(|_| invalid("vp_token presentation claims are invalid"))
}

fn validate_presentation_claims<'a>(
    presentation: &'a PresentationClaims,
    state: &PresentationStateClaims,
) -> Result<&'a [String], OAuthError> {
    let now = get_current_timestamp();

    if presentation.nonce != state.nonce {
        return Err(invalid("vp_token presentation nonce is invalid"));
    }
    let (presentation_types, credentials) = if let Some(body) = &presentation.vp {
        // Boruta wallet omits aud and JWT time claims. Their absence is accepted
        // because the nonce is bound to short-lived authenticated presentation
        // state; when these claims are present, their constraints still apply.
        if presentation
            .aud
            .as_deref()
            .is_some_and(|audience| audience != state.client_id)
        {
            return Err(invalid("vp_token presentation audience is invalid"));
        }
        if presentation.iat.is_some_and(|iat| iat > now)
            || presentation.nbf.is_some_and(|nbf| nbf > now)
            || presentation.exp.is_some_and(|exp| exp <= now)
            || presentation
                .iat
                .zip(presentation.exp)
                .is_some_and(|(iat, exp)| exp <= iat)
        {
            return Err(invalid("vp_token presentation time claims are invalid"));
        }

        (&body.presentation_types, &body.credentials)
    } else {
        if presentation.id.as_deref() != Some(&state.presentation_definition_id) {
            return Err(invalid("vp_token presentation definition id is invalid"));
        }
        if presentation.sub.as_deref() != Some(&presentation.iss) {
            return Err(invalid("vp_token presentation issuer must equal subject"));
        }

        (&presentation.presentation_types, &presentation.credentials)
    };

    if !presentation_types
        .iter()
        .any(|presentation_type| presentation_type == "VerifiablePresentation")
    {
        return Err(invalid("vp_token must be a VerifiablePresentation"));
    }
    if credentials.len() != 1 {
        return Err(invalid(
            "vp_token presentation must contain exactly one credential",
        ));
    }

    Ok(credentials)
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

fn invalid(description: &str) -> OAuthError {
    OAuthError::invalid_request(description)
}
