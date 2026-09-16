use serde::Deserialize;

use crate::{
    config::Config, errors::OAuthError, resources::presentation_state::PresentationStateClaims,
};

const VP_FORMAT: &str = "jwt_vp";
const VC_FORMAT: &str = "jwt_vc";
const VP_PATH: &str = "$";
const VC_PATH: &str = "$.vp.verifiableCredential[0]";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresentationSubmission {
    id: String,
    definition_id: Option<String>,
    descriptor_map: Vec<DescriptorMap>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescriptorMap {
    id: String,
    format: String,
    path: String,
    path_nested: NestedDescriptorMap,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NestedDescriptorMap {
    id: Option<String>,
    format: String,
    path: String,
}

pub const SUPPORTED_WALLET_ERRORS: &[&str] = &[
    "access_denied",
    "invalid_request",
    "vp_formats_not_supported",
    "wallet_unavailable",
];

pub trait ValidateEncoding {
    fn request_content_type(&self) -> Option<&str>;
}

pub trait ValidateWalletError {
    fn request_wallet_error(&self) -> Option<&str>;
    fn request_vp_token(&self) -> Option<&str>;
    fn request_presentation_submission(&self) -> Option<&str>;
    fn add_wallet_error(&mut self, error: String);
}

pub trait Validate {
    fn request_presentation_submission(&self) -> Option<&str>;
    fn presentation_state_claims(&self) -> Option<&PresentationStateClaims>;
    fn mark_presentation_submission_validated(&mut self);
}

/// Requires a form URL-encoded OpenID4VP direct-post response.
///
/// Parameters on the media type are accepted and its name is compared case-insensitively. This
/// action validates the HTTP representation without changing request state.
///
/// # Errors
///
/// Returns `invalid_request` when `Content-Type` is absent or is not
/// `application/x-www-form-urlencoded`.
pub fn validate_encoding<T: ValidateEncoding>(request: T) -> Result<T, OAuthError> {
    let media_type = request
        .request_content_type()
        .and_then(|content_type| content_type.split(';').next())
        .map(str::trim);

    if !media_type.is_some_and(|media_type| {
        media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(OAuthError::invalid_request(
            "presentation response content-type must be application/x-www-form-urlencoded",
        ));
    }

    Ok(request)
}

/// Validates an allowlisted negative wallet response that contains no success artifacts.
///
/// The response must contain a supported wallet error and must not mix that error with a VP token
/// or presentation submission. A valid error value is added to response state for downstream
/// redirection.
///
/// # Errors
///
/// Returns `invalid_request` for a missing or unsupported error or for mixed success and error
/// fields.
pub fn validate_wallet_error<T: ValidateWalletError>(mut request: T) -> Result<T, OAuthError> {
    let error = request
        .request_wallet_error()
        .ok_or_else(|| OAuthError::invalid_request("wallet error is required"))?;

    if request.request_vp_token().is_some() {
        return Err(OAuthError::invalid_request(
            "wallet error response must not include vp_token",
        ));
    }
    if request.request_presentation_submission().is_some() {
        return Err(OAuthError::invalid_request(
            "wallet error response must not include presentation_submission",
        ));
    }

    if !SUPPORTED_WALLET_ERRORS.contains(&error) {
        return Err(OAuthError::invalid_request("wallet error is unsupported"));
    }

    request.add_wallet_error(error.to_owned());
    Ok(request)
}

/// Validates that the submitted VP/VC descriptor mapping satisfies the restored request state.
///
/// Requires presentation state to be validated first. It accepts the standard definition-bound
/// mapping or the supported credential-bound mapping, each with exactly one VP/VC descriptor, then
/// marks the submission validated for presentation verification.
///
/// # Errors
///
/// Returns `invalid_request` for missing prerequisite state, malformed JSON, empty identifiers,
/// multiple descriptors, or definition, descriptor, format, or JSON-path mismatches.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let encoded_submission = request
        .request_presentation_submission()
        .ok_or_else(|| OAuthError::invalid_request("presentation_submission is required"))?;
    let submission: PresentationSubmission =
        serde_json::from_str(encoded_submission).map_err(|_| {
            OAuthError::invalid_request("presentation_submission must be a JSON object")
        })?;
    let state = request.presentation_state_claims().ok_or_else(|| {
        OAuthError::invalid_request("state must be validated before presentation_submission")
    })?;
    let configured_descriptor = |id: &str| {
        Config::global().credentials.iter().any(|credential| {
            credential
                .credential_types
                .iter()
                .any(|credential_type| credential_type == id)
        })
    };

    if submission.id.is_empty() {
        return Err(OAuthError::invalid_request(
            "presentation_submission id is required",
        ));
    }
    if submission
        .definition_id
        .as_deref()
        .is_some_and(|definition_id| definition_id != state.presentation_definition_id)
    {
        return Err(OAuthError::invalid_request(
            "presentation_submission definition_id is invalid",
        ));
    }
    let [descriptor] = submission.descriptor_map.as_slice() else {
        return Err(OAuthError::invalid_request(
            "presentation_submission must contain exactly one descriptor",
        ));
    };
    let standard_descriptor = submission.definition_id.is_some()
        && descriptor.id == state.input_descriptor_id
        && descriptor.path_nested.id.as_deref() == Some(&state.input_descriptor_id)
        && descriptor.format == VP_FORMAT
        && descriptor.path == VP_PATH
        && descriptor.path_nested.format == VC_FORMAT
        && descriptor.path_nested.path == VC_PATH;
    let credential_bound_descriptor = submission.definition_id.is_none()
        && configured_descriptor(&descriptor.id)
        && descriptor
            .path_nested
            .id
            .as_deref()
            .is_some_and(|id| !id.is_empty())
        && descriptor.format == VP_FORMAT
        && descriptor.path == VP_PATH
        && descriptor.path_nested.format == VC_FORMAT
        && descriptor.path_nested.path == "$.verifiableCredential[0]";

    if !standard_descriptor && !credential_bound_descriptor {
        let descriptor_id_is_valid = descriptor.id == state.input_descriptor_id
            && descriptor.path_nested.id.as_deref() == Some(&state.input_descriptor_id);
        let credential_bound_id_is_valid = configured_descriptor(&descriptor.id)
            && descriptor
                .path_nested
                .id
                .as_deref()
                .is_some_and(|id| !id.is_empty())
            && submission.definition_id.is_none();
        if !descriptor_id_is_valid && !credential_bound_id_is_valid {
            return Err(OAuthError::invalid_request(
                "presentation_submission descriptor id is invalid",
            ));
        }

        return Err(OAuthError::invalid_request(
            "presentation_submission descriptor mapping is invalid",
        ));
    }

    request.mark_presentation_submission_validated();
    Ok(request)
}
