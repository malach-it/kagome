use crate::{
    config::{Config, PresentationDefinitionConfig},
    errors::OAuthError,
};

pub trait Select {
    fn requested_scope(&self) -> Option<&str>;
    fn add_presentation_definition(&mut self, definition: PresentationDefinitionConfig);
}

pub fn select<T: Select>(mut request: T) -> Result<T, OAuthError> {
    let configured = &Config::global().presentation_definitions;
    let requested_identifiers: Vec<_> = request
        .requested_scope()
        .into_iter()
        .flat_map(str::split_ascii_whitespace)
        .collect();
    let matching: Vec<_> = configured
        .iter()
        .filter(|presentation| requested_identifiers.contains(&presentation.identifier.as_str()))
        .collect();
    let selected = match matching.as_slice() {
        [selected] => (*selected).clone(),
        [] if requested_identifiers.is_empty() && configured.len() == 1 => configured[0].clone(),
        _ => {
            return Err(OAuthError::invalid_request(
                "scope must select exactly one configured presentation definition",
            ));
        }
    };

    request.add_presentation_definition(selected);
    Ok(request)
}
