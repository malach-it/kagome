use crate::{
    resources::federated_server,
    unit::{KagomeRequest, parse_query_parameter},
};

#[derive(Debug)]
pub struct FederationCallbackRequest {
    pub response: FederationCallbackResponse,
    pub code: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug)]
pub struct FederationCallbackResponse {
    pub authorization_code: Option<String>,
    pub federation_state: Option<federated_server::FederationState>,
}

impl FederationCallbackRequest {
    pub fn from_request(request: &KagomeRequest) -> Self {
        Self {
            response: FederationCallbackResponse {
                authorization_code: None,
                federation_state: None,
            },
            code: parse_query_parameter(request, "code"),
            error: parse_query_parameter(request, "error"),
            error_description: parse_query_parameter(request, "error_description"),
            state: parse_query_parameter(request, "state"),
        }
    }
}

impl federated_server::ValidateCallbackState for FederationCallbackRequest {
    fn request_state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    fn add_federation_state(&mut self, state: federated_server::FederationState) {
        self.response.federation_state = Some(state);
    }
}

impl federated_server::ValidateCallback for FederationCallbackRequest {
    fn request_authorization_code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    fn request_error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    fn request_error_description(&self) -> Option<&str> {
        self.error_description.as_deref()
    }

    fn add_authorization_code(&mut self, authorization_code: String) {
        self.response.authorization_code = Some(authorization_code);
    }
}
