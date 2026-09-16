use std::{error::Error, fmt, fs, io, path::Path, sync::OnceLock};

use minijinja::{Environment, ErrorKind, Value, context};

const BASE: &str = "base.html";
const AUTHORIZATION_ERROR: &str = "authorization_error.html";
const WALLET_AUTHORIZATION: &str = "wallet_authorization.html";
const TEMPLATE_DIRECTORY: &str = "templates";

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

pub fn authorization_error(
    client_id: Option<&str>,
    error: &str,
    error_description: &str,
) -> Result<String, TemplateError> {
    render_for_client(
        client_id,
        AUTHORIZATION_ERROR,
        context! {
            error => escaped_html(error),
            error_description => escaped_html(error_description),
            style_nonce => "",
        },
    )
}

pub fn wallet_authorization(
    client_id: &str,
    authorization_uri: &str,
    qr_uri: &str,
    qr_svg: &str,
    script_nonce: &str,
) -> Result<String, TemplateError> {
    render_for_client(
        Some(client_id),
        WALLET_AUTHORIZATION,
        context! {
            authorization_uri => escaped_html(authorization_uri),
            qr_uri => escaped_html(qr_uri),
            qr_svg => qr_svg,
            script_nonce => script_nonce,
            style_nonce => script_nonce,
        },
    )
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
    build_environment_from(Path::new(TEMPLATE_DIRECTORY))
}

fn build_environment_from(directory: &Path) -> Result<Environment<'static>, TemplateError> {
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
    load_client_templates(&mut environment, directory)?;

    Ok(environment)
}

fn load_client_templates(
    environment: &mut Environment<'static>,
    directory: &Path,
) -> Result<(), TemplateError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(TemplateError(format!(
                "could not read template directory {}: {error}",
                directory.display()
            )));
        }
    };

    for entry in entries {
        let entry = entry.map_err(|error| {
            TemplateError(format!(
                "could not read template directory entry in {}: {error}",
                directory.display()
            ))
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_client_template_name(&name) {
            continue;
        }
        let path = entry.path();
        let source = fs::read_to_string(&path).map_err(|error| {
            TemplateError(format!(
                "could not read template {}: {error}",
                path.display()
            ))
        })?;
        environment
            .add_template_owned(name, source)
            .map_err(TemplateError::from)?;
    }

    Ok(())
}

fn is_client_template_name(name: &str) -> bool {
    [AUTHORIZATION_ERROR, WALLET_AUTHORIZATION]
        .iter()
        .any(|template| {
            name.strip_suffix(template)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
        })
}

fn render_for_client(
    client_id: Option<&str>,
    name: &str,
    context: minijinja::Value,
) -> Result<String, TemplateError> {
    render_for_client_in(
        environment().map_err(Clone::clone)?,
        client_id,
        name,
        context,
    )
}

fn render_for_client_in(
    environment: &Environment<'_>,
    client_id: Option<&str>,
    name: &str,
    context: minijinja::Value,
) -> Result<String, TemplateError> {
    let Some(custom_name) = client_id.and_then(|client_id| client_template_name(client_id, name))
    else {
        return render(environment, name, context).map_err(TemplateError::from);
    };

    match render(environment, &custom_name, context.clone()) {
        Err(error) if error.kind() == ErrorKind::TemplateNotFound => {
            render(environment, name, context).map_err(TemplateError::from)
        }
        result => result.map_err(TemplateError::from),
    }
}

fn client_template_name(client_id: &str, name: &str) -> Option<String> {
    if client_id.is_empty() || client_id.contains(['/', '\\']) {
        return None;
    }

    Some(format!("{client_id}.{name}"))
}

fn render(
    environment: &Environment<'_>,
    name: &str,
    context: minijinja::Value,
) -> Result<String, minijinja::Error> {
    environment
        .get_template(name)
        .and_then(|template| template.render(context))
}

impl From<minijinja::Error> for TemplateError {
    fn from(error: minijinja::Error) -> Self {
        Self(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static TEMPLATE_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn authorization_error_renders_and_escapes_error_attributes() {
        let html = authorization_error(
            None,
            "invalid_<request>",
            "<script>alert('unsafe')</script>",
        )
        .expect("authorization error template should render");

        assert!(html.contains("invalid_&lt;request&gt;"), "{html}");
        assert!(
            html.contains("&lt;script&gt;alert(&#39;unsafe&#39;)&lt;/script&gt;"),
            "{html}"
        );
        assert!(!html.contains("<script>alert"));
    }

    #[test]
    fn wallet_authorization_escapes_uris_and_preserves_generated_svg() {
        let html = wallet_authorization(
            "client_id",
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
        assert!(html.contains("<script nonce=\"nonce\">"));
    }

    #[test]
    fn prefers_client_authorization_error_template_and_falls_back_to_default() {
        let directory = template_directory();
        fs::write(
            directory.join("client_id.authorization_error.html"),
            "custom error {{ error }} {{ error_description }}",
        )
        .unwrap();
        let context = context! {
            error => escaped_html("invalid_request"),
            error_description => escaped_html("invalid description"),
            style_nonce => "",
        };
        let environment = build_environment_from(&directory).unwrap();
        let custom = render_for_client_in(
            &environment,
            Some("client_id"),
            AUTHORIZATION_ERROR,
            context.clone(),
        )
        .unwrap();
        let fallback = render_for_client_in(
            &environment,
            Some("other_client"),
            AUTHORIZATION_ERROR,
            context,
        )
        .unwrap();

        assert_eq!(custom, "custom error invalid_request invalid description");
        assert!(fallback.contains("invalid_request"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn prefers_client_wallet_authorization_template_and_falls_back_to_default() {
        let directory = template_directory();
        fs::write(
            directory.join("client_id.wallet_authorization.html"),
            "custom wallet {{ authorization_uri }}",
        )
        .unwrap();
        let context = context! {
            authorization_uri => escaped_html("https://wallet.example/authorize"),
            qr_uri => escaped_html("https://issuer.example/relay"),
            qr_svg => "<svg></svg>",
            script_nonce => "nonce",
            style_nonce => "nonce",
        };
        let environment = build_environment_from(&directory).unwrap();
        let custom = render_for_client_in(
            &environment,
            Some("client_id"),
            WALLET_AUTHORIZATION,
            context.clone(),
        )
        .unwrap();
        let fallback = render_for_client_in(
            &environment,
            Some("other_client"),
            WALLET_AUTHORIZATION,
            context,
        )
        .unwrap();

        assert_eq!(custom, "custom wallet https://wallet.example/authorize");
        assert!(fallback.contains("scan authorization request"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ignores_client_ids_that_could_escape_the_template_directory() {
        let directory = template_directory();
        let environment = build_environment_from(&directory).unwrap();
        let context = context! {
            error => escaped_html("invalid_request"),
            error_description => escaped_html("invalid description"),
            style_nonce => "",
        };

        let rendered = render_for_client_in(
            &environment,
            Some("../client_id"),
            AUTHORIZATION_ERROR,
            context,
        )
        .unwrap();

        assert!(rendered.contains("invalid_request"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn loads_client_templates_only_when_the_environment_is_built() {
        let directory = template_directory();
        let path = directory.join("client_id.authorization_error.html");
        fs::write(&path, "initial {{ error }}").unwrap();
        let environment = build_environment_from(&directory).unwrap();
        fs::write(&path, "changed {{ error }}").unwrap();

        let rendered = render_for_client_in(
            &environment,
            Some("client_id"),
            AUTHORIZATION_ERROR,
            context! {
                error => escaped_html("invalid_request"),
                error_description => escaped_html("invalid description"),
                style_nonce => "",
            },
        )
        .unwrap();

        assert_eq!(rendered, "initial invalid_request");
        fs::remove_dir_all(directory).unwrap();
    }

    fn template_directory() -> PathBuf {
        let sequence = TEMPLATE_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "kagome-template-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        directory
    }
}
