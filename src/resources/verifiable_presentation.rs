use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, Validation, decode, decode_header,
    get_current_timestamp,
    jwk::{Jwk, ThumbprintHash},
};
use serde::Deserialize;
use serde_json::Value;

use crate::errors::OAuthError;

use super::{
    crypto::SigningArtifact, presentation_state::PresentationStateClaims, self_issued_id_token,
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
    cnf: CredentialConfirmation,
}

#[derive(Debug, Deserialize)]
struct CredentialConfirmation {
    jwk: Jwk,
}

pub trait Validate {
    fn request_vp_token(&self) -> Option<&str>;
    fn presentation_state_claims(&self) -> Option<&PresentationStateClaims>;
    fn presentation_submission_validated(&self) -> bool;
    fn add_validated_presentation(&mut self, presentation: ValidatedPresentation);
}

/// Verifies the holder, credential, wallet binding, and requested presentation claims.
///
/// Requires presentation state and submission validation. It verifies the asymmetric VP signature,
/// optional ID-token key binding, nonce, audience and time claims, exactly one embedded issuer-signed
/// credential, the requested definition, and subject and confirmation-key holder binding. The
/// trusted subject and credential issuer are added to the request.
///
/// # Errors
///
/// Returns `invalid_request` for missing prerequisites or any malformed, unsupported, untrusted,
/// stale, wrongly addressed, definition-mismatched, or incorrectly bound VP or VC.
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
    if credential.cnf.jwk.thumbprint(ThumbprintHash::SHA256)
        != holder_jwk.thumbprint(ThumbprintHash::SHA256)
    {
        return Err(invalid(
            "vp_token presentation key must match the credential confirmation key",
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
    if presentation.aud.as_deref() != Some(&state.client_id) {
        return Err(invalid("vp_token presentation audience is invalid"));
    }
    if presentation.iat.is_none_or(|iat| iat > now)
        || presentation.exp.is_none_or(|exp| exp <= now)
        || presentation
            .iat
            .zip(presentation.exp)
            .is_none_or(|(iat, exp)| exp <= iat)
        || presentation.nbf.is_some_and(|nbf| nbf > now)
    {
        return Err(invalid("vp_token presentation time claims are invalid"));
    }
    let (presentation_types, credentials) = if let Some(body) = &presentation.vp {
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
    let credential_value = decode::<Value>(
        credential,
        &SigningArtifact::Credential
            .decoding_key()
            .map_err(|_| invalid("credential issuer key is invalid"))?,
        &validation,
    )
    .map_err(|_| invalid("presented credential is invalid or expired"))?
    .claims;
    let credential: CredentialClaims = serde_json::from_value(credential_value.clone())
        .map_err(|_| invalid("presented credential claims are invalid"))?;

    if credential.iss != state.credential_issuer {
        return Err(invalid("presented credential issuer is invalid"));
    }
    if credential.iat > get_current_timestamp() || credential.exp <= credential.iat {
        return Err(invalid("presented credential time claims are invalid"));
    }
    if !satisfies_presentation_definition(&credential_value, &state.presentation_definition) {
        return Err(invalid(
            "presented credential claims do not satisfy the query",
        ));
    }

    Ok(credential)
}

fn satisfies_presentation_definition(credential: &Value, definition: &Value) -> bool {
    definition
        .pointer("/input_descriptors/0/constraints/fields")
        .and_then(Value::as_array)
        .is_none_or(|fields| {
            fields
                .iter()
                .all(|field| satisfies_field(credential, field))
        })
}

fn satisfies_field(credential: &Value, field: &Value) -> bool {
    let Some(paths) = field.get("path").and_then(Value::as_array) else {
        return false;
    };
    let filter = field.get("filter");

    paths.iter().filter_map(Value::as_str).any(|path| {
        resolve_json_path(credential, path)
            .is_some_and(|value| filter.is_none_or(|filter| matches_filter(value, filter)))
    })
}

fn resolve_json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let path = path.strip_prefix("$.")?;
    path.split('.').try_fold(value, |value, segment| {
        let (name, index) = segment
            .strip_suffix(']')
            .and_then(|segment| segment.rsplit_once('['))
            .map_or((segment, None), |(name, index)| {
                (name, index.parse::<usize>().ok())
            });
        let value = value.get(name)?;
        index.map_or(Some(value), |index| value.get(index))
    })
}

fn matches_filter(value: &Value, filter: &Value) -> bool {
    let Some(filter) = filter.as_object() else {
        return false;
    };
    if filter
        .keys()
        .any(|keyword| !matches!(keyword.as_str(), "type" | "const" | "enum" | "contains"))
    {
        return false;
    }
    let type_matches = filter
        .get("type")
        .and_then(Value::as_str)
        .is_none_or(|expected| match expected {
            "array" => value.is_array(),
            "boolean" => value.is_boolean(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "null" => value.is_null(),
            "number" => value.is_number(),
            "object" => value.is_object(),
            "string" => value.is_string(),
            _ => false,
        });
    let const_matches = filter.get("const").is_none_or(|expected| value == expected);
    let enum_matches = filter
        .get("enum")
        .and_then(Value::as_array)
        .is_none_or(|expected| expected.contains(value));
    let contains_matches = filter.get("contains").is_none_or(|contains| {
        value
            .as_array()
            .is_some_and(|values| values.iter().any(|value| matches_filter(value, contains)))
    });

    type_matches && const_matches && enum_matches && contains_matches
}

fn invalid(description: &str) -> OAuthError {
    OAuthError::invalid_request(description)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::satisfies_presentation_definition;

    #[test]
    fn matches_supported_presentation_definition_fields() {
        let credential = json!({
            "vc": {"type": ["VerifiableCredential", "EmployeeCredential"]},
            "vct": "EmployeeCredential"
        });
        let definition = json!({
            "input_descriptors": [{
                "constraints": {"fields": [{
                    "path": ["$.vc.type"],
                    "filter": {
                        "type": "array",
                        "contains": {"const": "EmployeeCredential"}
                    }
                }, {
                    "path": ["$.vc.vct", "$.vct"],
                    "filter": {"enum": ["EmployeeCredential"]}
                }]}
            }]
        });

        assert!(satisfies_presentation_definition(&credential, &definition));
    }

    #[test]
    fn rejects_unsupported_presentation_definition_filter_keyword() {
        let credential = json!({"name": "Alice"});
        let definition = json!({
            "input_descriptors": [{
                "constraints": {"fields": [{
                    "path": ["$.name"],
                    "filter": {"pattern": "^Alice$"}
                }]}
            }]
        });

        assert!(!satisfies_presentation_definition(&credential, &definition));
    }
}
