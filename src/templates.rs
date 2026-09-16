use std::{error::Error, fmt, sync::OnceLock};

use base64::{Engine, engine::general_purpose::STANDARD};
use minijinja::{Environment, Value, context};

const BASE: &str = "base.html";
const AUTHORIZATION_ERROR: &str = "authorization_error.html";
const WALLET_AUTHORIZATION: &str = "wallet_authorization.html";

static ENVIRONMENT: OnceLock<Result<Environment<'static>, TemplateError>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateError(String);

impl fmt::Display for TemplateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for TemplateError {}

pub fn initialize() -> Result<(), TemplateError> {
    environment().map(|_| ()).map_err(Clone::clone)
}

pub fn authorization_error(error: &str, error_description: &str) -> Result<String, TemplateError> {
    render(
        AUTHORIZATION_ERROR,
        context! {
            brand_logo => brand_logo(),
            error => escaped_html(error),
            error_description => escaped_html(error_description),
            style_nonce => "",
        },
    )
}

pub fn wallet_authorization(
    authorization_uri: &str,
    qr_uri: &str,
    qr_svg: &str,
    script_nonce: &str,
) -> Result<String, TemplateError> {
    render(
        WALLET_AUTHORIZATION,
        context! {
            brand_logo => brand_logo(),
            authorization_uri => escaped_html(authorization_uri),
            qr_uri => escaped_html(qr_uri),
            qr_svg => qr_svg,
            script_nonce => script_nonce,
            style_nonce => script_nonce,
        },
    )
}

fn brand_logo() -> Value {
    let encoded = STANDARD.encode(include_bytes!("../templates/assets/malachit-logo.png"));

    Value::from_safe_string(format!("data:image/png;base64,{encoded}"))
}

fn escaped_html(value: &str) -> Value {
    let escaped = value.chars().fold(String::new(), |mut escaped, character| {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            character => escaped.push(character),
        }

        escaped
    });

    Value::from_safe_string(escaped)
}

fn environment() -> Result<&'static Environment<'static>, &'static TemplateError> {
    ENVIRONMENT.get_or_init(build_environment).as_ref()
}

fn build_environment() -> Result<Environment<'static>, TemplateError> {
    let mut environment = Environment::new();
    environment
        .add_template(BASE, include_str!("../templates/base.html"))
        .map_err(TemplateError::from)?;
    environment
        .add_template(
            AUTHORIZATION_ERROR,
            include_str!("../templates/authorization_error.html"),
        )
        .map_err(TemplateError::from)?;
    environment
        .add_template(
            WALLET_AUTHORIZATION,
            include_str!("../templates/wallet_authorization.html"),
        )
        .map_err(TemplateError::from)?;

    Ok(environment)
}

fn render(name: &str, context: minijinja::Value) -> Result<String, TemplateError> {
    environment()
        .map_err(Clone::clone)?
        .get_template(name)
        .map_err(TemplateError::from)?
        .render(context)
        .map_err(TemplateError::from)
}

impl From<minijinja::Error> for TemplateError {
    fn from(error: minijinja::Error) -> Self {
        Self(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_error_renders_and_escapes_error_attributes() {
        let html = authorization_error("invalid_<request>", "<script>alert('unsafe')</script>")
            .expect("authorization error template should render");

        assert!(html.contains("<h1>invalid_&lt;request&gt;</h1>"), "{html}");
        assert!(html.contains("alt=\"malach.it\""), "{html}");
        assert!(html.contains("src=\"data:image/png;base64,"), "{html}");
        assert!(
            html.contains("&lt;script&gt;alert(&#39;unsafe&#39;)&lt;/script&gt;"),
            "{html}"
        );
        assert!(!html.contains("<script>alert"));
    }

    #[test]
    fn wallet_authorization_escapes_uris_and_preserves_generated_svg() {
        let html = wallet_authorization(
            "https://wallet.example/open?a=1&b=\"unsafe\"",
            "https://issuer.example/relay?a=1&b=2",
            "<svg><path d=\"M0 0\"/></svg>",
            "nonce",
        )
        .expect("wallet authorization template should render");

        assert!(html.contains("a=1&amp;b=&quot;unsafe&quot;"));
        assert!(
            html.contains("data-qr-uri=\"https://issuer.example/relay?a=1&amp;b=2\""),
            "{html}"
        );
        assert!(html.contains("<svg><path d=\"M0 0\"/></svg>"));
        assert!(html.contains("<style nonce=\"nonce\">"));
        assert!(html.contains("alt=\"malach.it\""));
    }
}
