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

    fn add_response_type(&mut self, response_type: &ResponseType);
}

pub fn validate<T: Validate>(mut authorize_request: T) -> Result<T, OAuthError> {
    let response_type = parse(authorize_request.request_response_type())?;
    authorize_request.add_response_type(&response_type);

    Ok(authorize_request)
}

fn parse(response_type: Option<&str>) -> Result<ResponseType, OAuthError> {
    match response_type {
        Some("code") => Ok(ResponseType::Code),
        _ => Err(OAuthError::unsupported_response_type(
            &SUPPORTED_RESPONSE_TYPES,
        )),
    }
}
