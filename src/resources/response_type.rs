use crate::errors::OAuthError;

pub const PRE_AUTHORIZED_CODE: &str = "urn:ietf:params:oauth:response-type:pre-authorized_code";
pub const SUPPORTED_RESPONSE_TYPES: [&str; 4] = ["code", "token", "id_token", PRE_AUTHORIZED_CODE];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseType {
    Code,
    IdToken,
    PreAuthorizedCode,
    Token,
}

impl ResponseType {
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseType::Code => "code",
            ResponseType::IdToken => "id_token",
            ResponseType::PreAuthorizedCode => PRE_AUTHORIZED_CODE,
            ResponseType::Token => "token",
        }
    }
}

pub trait Validate {
    fn request_response_type(&self) -> Option<&str> {
        None
    }

    fn add_response_types(&mut self, response_types: Vec<ResponseType>);

    fn add_next_response_types(&mut self, _response_types: Vec<ResponseType>) {}
}

pub fn validate<T: Validate>(mut authorize_request: T) -> Result<T, OAuthError> {
    let response_types = parse(authorize_request.request_response_type())?;
    let next_response_types = response_types.iter().skip(1).copied().collect();

    authorize_request.add_response_types(response_types);
    authorize_request.add_next_response_types(next_response_types);

    Ok(authorize_request)
}

fn parse(response_type: Option<&str>) -> Result<Vec<ResponseType>, OAuthError> {
    let Some(response_type) = response_type else {
        return Err(OAuthError::unsupported_response_type(
            &SUPPORTED_RESPONSE_TYPES,
        ));
    };
    let response_types = response_type
        .split_whitespace()
        .map(|response_type| match response_type {
            "code" => Ok(ResponseType::Code),
            "id_token" => Ok(ResponseType::IdToken),
            PRE_AUTHORIZED_CODE => Ok(ResponseType::PreAuthorizedCode),
            "token" => Ok(ResponseType::Token),
            _ => Err(OAuthError::unsupported_response_type(
                &SUPPORTED_RESPONSE_TYPES,
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;

    if response_types.is_empty() {
        return Err(OAuthError::unsupported_response_type(
            &SUPPORTED_RESPONSE_TYPES,
        ));
    }

    if response_types.contains(&ResponseType::PreAuthorizedCode) && response_types.len() != 1 {
        return Err(OAuthError::invalid_final_response_type());
    }

    validate_final_response_type_is_final(&response_types)?;

    Ok(response_types)
}

fn validate_final_response_type_is_final(
    response_types: &[ResponseType],
) -> Result<(), OAuthError> {
    if response_types
        .iter()
        .enumerate()
        .any(|(index, response_type)| {
            *response_type == ResponseType::Token && index + 1 != response_types.len()
        })
    {
        return Err(OAuthError::invalid_final_response_type());
    }

    let is_code_id_token_token_response_type = matches!(
        response_types,
        [
            ResponseType::Code,
            ResponseType::IdToken,
            ResponseType::Token
        ]
    );
    let is_id_token_token_response_type =
        matches!(response_types, [ResponseType::IdToken, ResponseType::Token]);

    if !is_code_id_token_token_response_type
        && !is_id_token_token_response_type
        && response_types
            .iter()
            .enumerate()
            .any(|(index, response_type)| {
                *response_type == ResponseType::IdToken && index + 1 != response_types.len()
            })
    {
        return Err(OAuthError::invalid_final_response_type());
    }

    Ok(())
}
