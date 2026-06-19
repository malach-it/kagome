use crate::errors::OAuthError;

pub const SUPPORTED_RESPONSE_TYPES: [&str; 1] = ["code"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseType {
    Code,
}

impl ResponseType {
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseType::Code => "code",
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
            _ => Err(OAuthError::unsupported_response_type(
                &SUPPORTED_RESPONSE_TYPES,
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;

    if !response_types.is_empty() {
        return Ok(response_types);
    }

    Err(OAuthError::unsupported_response_type(
        &SUPPORTED_RESPONSE_TYPES,
    ))
}
