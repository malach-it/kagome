use std::sync::Once;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kagome::{
    config::{AgentProviderConfig, AgentProviderJwks, Config},
    errors::OAuthErrorCode,
    resources::http_signature::{
        AGENT_TOKEN_TYPE, KeyParameter, Validate, VerifiedSignatureKey, parse_signature_key,
        validate,
    },
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

const ISSUER: &str = "https://agents.example";
const SUBJECT: &str = "aauth:assistant@agents.example";
const KID: &str = "provider-1";

#[test]
fn parses_signature_key_members_and_typed_parameters_in_wire_order() {
    let members = parse_signature_key(
        r#" z=jwt;jwt="a,b;c=\"word\"\\end"; flag;off=?0,  a=x509;cert=:YWJj: "#,
    )
    .unwrap();
    let [first, second] = members.as_slice() else {
        panic!("expected two members");
    };
    assert_eq!((first.label, first.scheme), ("z", "jwt"));
    assert_eq!(
        first.parameters["jwt"],
        KeyParameter::String(r#"a,b;c="word"\end"#.to_owned())
    );
    assert_eq!(first.parameters["flag"], KeyParameter::Boolean(true));
    assert_eq!(first.parameters["off"], KeyParameter::Boolean(false));
    assert_eq!((second.label, second.scheme), ("a", "x509"));
    assert_eq!(
        second.parameters["cert"],
        KeyParameter::Bytes(b"abc".to_vec())
    );
}

#[test]
fn rejects_malformed_or_ambiguous_dictionary_members() {
    for field in [
        "",
        " ",
        "sig",
        "1sig=jwt",
        "Sig=jwt",
        "sig =jwt",
        "sig= jwt",
        "sig=\"jwt\"",
        "sig=(jwt)",
        "sig=jwt,",
        "sig=jwt,,other=jwt",
        "sig=jwt,sig=jwt",
        "sig=jwt;",
        r#"sig=jwt;jwt="one";jwt="two""#,
        r#"sig=jwt;jwt="unterminated"#,
        r#"sig=jwt;jwt="invalid\q""#,
        "sig=jwt;jwt=\"line\nbreak\"",
        "sig=jwt;jwt=\"é\"",
        "sig=jwt;jwt=\"complete\"garbage",
        "sig=jwt;flag=?2",
        "sig=jwt;flag=?10",
        "sig=x509;cert=:%%:",
        "sig=x509;cert=:YWJj",
        "sig=jwt;jwt=token",
        "sig=jwt;ext=123",
    ] {
        assert_eq!(
            parse_signature_key(field).unwrap_err().kind,
            OAuthErrorCode::InvalidRequest,
            "{field:?}"
        );
    }
}

#[derive(Debug)]
struct Request<'a> {
    fields: Vec<&'a str>,
    keys: Vec<VerifiedSignatureKey>,
}

impl Validate for Request<'_> {
    fn signature_key_fields(&self) -> &[&str] {
        &self.fields
    }

    fn add_verified_signature_keys(&mut self, keys: Vec<VerifiedSignatureKey>) {
        self.keys = keys;
    }
}

fn public_jwk(key: &Ed25519KeyPair) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
    })
}

fn provider_with_issuer(issuer: &str, key: &Ed25519KeyPair) -> AgentProviderConfig {
    let mut jwk = public_jwk(key);
    jwk["kid"] = json!(KID);
    AgentProviderConfig {
        issuer: issuer.to_owned(),
        jwks: Some(AgentProviderJwks {
            keys: vec![serde_json::from_value(jwk).unwrap()],
        }),
        jwks_uri: None,
    }
}

fn header() -> Value {
    json!({"typ": AGENT_TOKEN_TYPE, "alg": "Ed25519", "kid": KID})
}

fn claims(key: &Ed25519KeyPair) -> Value {
    let now = jsonwebtoken::get_current_timestamp();
    json!({
        "iss": ISSUER,
        "sub": SUBJECT,
        "dwk": "aauth-agent.json",
        "jti": "test-1",
        "iat": now,
        "exp": now + 300,
        "cnf": {"jwk": public_jwk(key)},
    })
}

fn sign(key: &Ed25519KeyPair, header: Value, claims: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(header.to_string());
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
    let message = format!("{header}.{claims}");
    let signature = URL_SAFE_NO_PAD.encode(key.sign(message.as_bytes()).as_ref());
    format!("{message}.{signature}")
}

fn request<'a>(fields: &[&'a str]) -> Request<'a> {
    static CONFIGURE: Once = Once::new();
    CONFIGURE.call_once(|| {
        let provider_key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
        let next_provider_key = Ed25519KeyPair::from_seed_unchecked(&[4; 32]).unwrap();
        let other_key = Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap();
        let mut provider = provider_with_issuer(ISSUER, &provider_key);
        let mut next_jwk = public_jwk(&next_provider_key);
        next_jwk["kid"] = json!("provider-next");
        provider
            .jwks
            .as_mut()
            .unwrap()
            .keys
            .push(serde_json::from_value(next_jwk).unwrap());
        provider.jwks_uri = Some("https://127.0.0.1:1/jwks".to_owned());

        let mut config: Config =
            serde_yaml_ng::from_str(include_str!("../kagome.example.yaml")).unwrap();
        config.agent_providers = vec![
            provider,
            provider_with_issuer("https://other.example", &other_key),
        ];
        Config::set_global(config).unwrap();
    });
    Request {
        fields: fields.to_vec(),
        keys: Vec::new(),
    }
}

#[test]
fn verifies_provider_signature_and_retains_separate_agent_keys_for_each_label() {
    let provider_key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let next_provider_key = Ed25519KeyPair::from_seed_unchecked(&[4; 32]).unwrap();
    let agent_key = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let second_agent_key = Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap();
    let first = sign(&provider_key, header(), claims(&agent_key));
    let mut next_header = header();
    next_header["kid"] = json!("provider-next");
    let second = sign(&next_provider_key, next_header, claims(&second_agent_key));
    let field = format!(r#"first=jwt;jwt="{first}", second=jwt;jwt="{second}""#);

    let result = validate(request(&[&field])).unwrap();
    let [first, second] = result.keys.as_slice() else {
        panic!("expected two verified keys");
    };
    for (entry, label, key) in [
        (first, "first", agent_key),
        (second, "second", second_agent_key),
    ] {
        assert_eq!(entry.label, label);
        assert_eq!(entry.agent_token.issuer, ISSUER);
        assert_eq!(entry.agent_token.subject, SUBJECT);
        assert_eq!(
            serde_json::to_value(&entry.agent_token.public_jwk).unwrap(),
            public_jwk(&key)
        );
    }
}

#[test]
fn rejects_missing_repeated_or_unsupported_signature_key_fields() {
    for (fields, error) in [
        (vec![], "Signature-Key is required"),
        (
            vec!["sig=jwt", "other=jwt"],
            "Signature-Key must appear once",
        ),
        (vec!["sig=hwk"], "Signature-Key scheme must be jwt"),
        (
            vec!["sig=jwt"],
            "Signature-Key jwt parameter must be a string",
        ),
        (
            vec!["sig=jwt;jwt=?1"],
            "Signature-Key jwt parameter must be a string",
        ),
    ] {
        assert_eq!(
            validate(request(&fields)).unwrap_err().error_description,
            error
        );
    }
}

#[test]
fn rejects_tokens_that_do_not_chain_to_the_configured_provider() {
    let provider_key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let agent_key = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let other_key = Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap();
    let check = |token: String, description| {
        let field = format!(r#"sig=jwt;jwt="{token}""#);
        let error = validate(request(&[&field])).unwrap_err();
        assert_eq!(error.kind, OAuthErrorCode::InvalidRequest);
        assert_eq!(error.error_description, description);
    };

    let mut unknown_issuer = claims(&agent_key);
    unknown_issuer["iss"] = json!("https://unconfigured.example");
    check(
        sign(&provider_key, header(), unknown_issuer),
        "agent token issuer is not trusted",
    );

    let mut unknown_kid = header();
    unknown_kid["kid"] = json!("unknown");
    let mut other_issuer_claims = claims(&agent_key);
    other_issuer_claims["iss"] = json!("https://other.example");
    other_issuer_claims["sub"] = json!("aauth:assistant@other.example");
    check(
        sign(&other_key, unknown_kid, other_issuer_claims),
        "agent token kid is not trusted for its issuer",
    );

    let mut critical_extension = header();
    critical_extension["crit"] = json!(["b64"]);
    critical_extension["b64"] = json!(false);
    check(
        sign(&provider_key, critical_extension, claims(&agent_key)),
        "agent token uses unsupported JOSE header parameters",
    );

    let mut wrong_algorithm = header();
    wrong_algorithm["alg"] = json!("EdDSA");
    check(
        sign(&provider_key, wrong_algorithm, claims(&agent_key)),
        "agent token algorithm does not match the provider key",
    );

    for key in [&agent_key, &other_key] {
        check(
            sign(key, header(), claims(&agent_key)),
            "agent token provider signature is invalid",
        );
    }
}

#[test]
fn rejects_expired_tokens_and_invalid_agent_claims() {
    let provider_key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let agent_key = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let valid = sign(&provider_key, header(), claims(&agent_key));
    for (claim, value, description) in [
        (
            "exp",
            json!(jsonwebtoken::get_current_timestamp()),
            "agent token expiration is invalid",
        ),
        (
            "dwk",
            json!("another-document.json"),
            "agent token is malformed or has invalid claims",
        ),
        (
            "sub",
            json!("aauth:assistant@other.example"),
            "agent token is malformed or has invalid claims",
        ),
        (
            "ps",
            json!("http://person.example"),
            "agent token is malformed or has invalid claims",
        ),
        (
            "cnf",
            json!({"jwk": {"kty": "oct", "alg": "HS256", "k": "AA"}}),
            "agent token cnf.jwk must be an asymmetric public signing key",
        ),
    ] {
        let mut invalid = claims(&agent_key);
        invalid[claim] = value;
        let token = sign(&provider_key, header(), invalid);
        let field = format!(r#"first=jwt;jwt="{valid}", second=jwt;jwt="{token}""#);
        assert_eq!(
            validate(request(&[&field])).unwrap_err().error_description,
            description
        );
    }
}
