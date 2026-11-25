use axum::http::Uri;

use super::responses::{
    agent_resource_error_response, log_agent_resource_failure, logged_response,
};
use crate::{
    requests::AgentResourceRequest,
    resources::{agent_ssh, http_signature},
    unit::KagomeRequest,
};

pub fn handle_agent_resource_ssh(request: &KagomeRequest, target: Option<&Uri>) -> String {
    match http_signature::validate(AgentResourceRequest::from_request(request, target))
        .and_then(http_signature::verify_message)
        .and_then(agent_ssh::register)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => {
            log_agent_resource_failure("POST", &error);
            agent_resource_error_response(&error)
        }
    }
}
