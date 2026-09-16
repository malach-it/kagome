fn configured_clients() -> Vec<kagome::config::ClientConfig> {
    vec![kagome::config::ClientConfig {
        client_id: "client_id".to_owned(),
        public: Some("example.com".to_owned()),
        client_secret: "client_secret".to_owned(),
        password_file: None,
        redirect_uris: vec!["https://client.example.com/callback".to_owned()],
        supported_grant_types: kagome::resources::grant_type::GrantType::ALL.to_vec(),
        supported_response_types: kagome::resources::response_type::ResponseType::ALL.to_vec(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        require_wallet_binding: false,
        qr_code: false,
        federated_server: None,
    }]
}

mod resources {
    mod scope {
        #[derive(Debug)]
        struct Request {
            scope: Option<String>,
            client_id: Option<String>,
        }

        impl kagome::resources::scope::Validate for Request {
            fn request_scope(&self) -> Option<&str> {
                self.scope.as_deref()
            }

            fn validated_client_id(&self) -> Option<&str> {
                self.client_id.as_deref()
            }
        }

        #[test]
        fn accepts_omitted_and_authorized_scopes() {
            for scope in [None, Some("openid"), Some("openid profile")] {
                let request = Request {
                    scope: scope.map(str::to_owned),
                    client_id: Some("client_id".to_owned()),
                };

                kagome::resources::scope::validate_with_clients(
                    request,
                    &super::super::configured_clients(),
                )
                .expect("configured scopes should be accepted");
            }
        }

        #[test]
        fn rejects_empty_and_unauthorized_scopes() {
            for (scope, description) in [
                (" ", "scope must not be empty"),
                ("openid admin", "scope is not authorized for client: admin"),
            ] {
                let request = Request {
                    scope: Some(scope.to_owned()),
                    client_id: Some("client_id".to_owned()),
                };

                let error = kagome::resources::scope::validate_with_clients(
                    request,
                    &super::super::configured_clients(),
                )
                .unwrap_err();

                assert_eq!(error.error, "invalid_scope");
                assert_eq!(error.error_description, description);
            }
        }

        #[test]
        fn resolves_scopes_for_public_client_identifier() {
            let request = Request {
                scope: Some("openid".to_owned()),
                client_id: Some("username@example.com".to_owned()),
            };

            kagome::resources::scope::validate_with_clients(
                request,
                &super::super::configured_clients(),
            )
            .expect("public client should use the matching host configuration");
        }
    }

    mod access_token {
        #[test]
        fn generates_cose_encrypt0_containing_client_id() {
            let request = token_request(Some("client_id"));
            let mut token_response =
                kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            kagome::resources::client_credentials::Validate::add_client_credentials(
                &mut token_response,
                kagome::resources::client_credentials::ClientCredentials {
                    client_id: "client_id".to_owned(),
                    client_secret: Some("client_secret".to_owned()),
                    redirect_uri: None,
                    authenticated_username: None,
                },
            );
            let generated_at = issued_at_timestamp();
            let token_response = kagome::resources::access_token::generate(token_response).unwrap();
            let access_token = token_response.response.access_token.as_ref().unwrap();

            let payload = decode_payload(&access_token.value);

            assert!(!access_token.value.contains('.'));
            assert_eq!(
                payload.token_type,
                kagome::resources::access_token::TOKEN_TYPE
            );
            assert_eq!(access_token.payload.token_type, payload.token_type);
            assert_eq!(access_token.payload.client_id, payload.client_id);
            assert_eq!(access_token.payload.username, payload.username);
            assert_eq!(access_token.payload.iat, payload.iat);
            assert_eq!(access_token.payload.exp, payload.exp);
            assert_eq!(
                access_token.expires_in,
                kagome::resources::access_token::ACCESS_TOKEN_TTL_SECONDS
            );
            assert_eq!(access_token.expires_in, payload.exp - payload.iat);
            assert_eq!(payload.client_id, "client_id");
            assert_eq!(payload.username, None);
            assert!(payload.iat >= generated_at);
            assert!(payload.iat <= issued_at_timestamp());
            assert_eq!(
                payload.exp,
                payload.iat + kagome::resources::access_token::ACCESS_TOKEN_TTL_SECONDS
            );
        }

        #[test]
        fn returns_oauth_error_for_missing_client_id() {
            let request = token_request(None);
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error = kagome::resources::access_token::generate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id is required");
        }

        fn decode_payload(
            access_token: &str,
        ) -> kagome::resources::access_token::AccessTokenClaims {
            kagome::resources::access_token::decode_cose_payload(access_token).unwrap()
        }

        fn issued_at_timestamp() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }

        fn token_request(client_id: Option<&str>) -> kagome::unit::KagomeRequest {
            let mut parameters = vec![
                "client_secret=client_secret".to_owned(),
                "grant_type=client_credentials".to_owned(),
            ];
            if let Some(client_id) = client_id {
                parameters.push(format!("client_id={client_id}"));
            }

            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![kagome::unit::HttpHeader {
                    name: "content-type".to_owned(),
                    value: "application/x-www-form-urlencoded".to_owned(),
                }],
                query_params: Vec::new(),
                body: parameters.join("&"),
            }
        }
    }

    mod metadata_policy {
        #[derive(Debug)]
        struct Request {
            metadata_policy: Option<String>,
            authorization_code: Option<String>,
            client_id: Option<String>,
            response: Response,
        }

        #[derive(Debug)]
        struct Response {
            metadata_policy: Option<kagome::resources::metadata_policy::MetadataPolicy>,
        }

        impl Request {
            fn new(metadata_policy: Option<&str>) -> Self {
                Self {
                    metadata_policy: metadata_policy.map(str::to_owned),
                    authorization_code: None,
                    client_id: None,
                    response: Response {
                        metadata_policy: None,
                    },
                }
            }
        }

        impl kagome::resources::metadata_policy::Validate for Request {
            fn request_metadata_policy(&self) -> Option<&str> {
                self.metadata_policy.as_deref()
            }

            fn request_authorization_code(&self) -> Option<&str> {
                self.authorization_code.as_deref()
            }

            fn client_id(&self) -> Option<&str> {
                self.client_id.as_deref()
            }

            fn add_metadata_policy(
                &mut self,
                metadata_policy: kagome::resources::metadata_policy::MetadataPolicy,
            ) {
                self.response.metadata_policy = Some(metadata_policy);
            }
        }

        #[test]
        fn validates_json_string_metadata_policy() {
            let request = Request::new(Some("\"profile\""));

            let request = kagome::resources::metadata_policy::validate(request).unwrap();

            assert_eq!(
                request.response.metadata_policy,
                Some(kagome::resources::metadata_policy::MetadataPolicy::String(
                    "profile".to_owned()
                ))
            );
        }

        #[test]
        fn validates_username_superset_metadata_policy() {
            let request = Request::new(Some("{\"username\":{\"superset_of\":[]}}"));

            let request = kagome::resources::metadata_policy::validate(request).unwrap();

            assert_eq!(
                request.response.metadata_policy,
                Some(
                    kagome::resources::metadata_policy::MetadataPolicy::Username {
                        superset_of: Vec::new()
                    }
                )
            );
        }

        #[test]
        fn ignores_missing_metadata_policy() {
            let request = Request::new(None);

            let request = kagome::resources::metadata_policy::validate(request).unwrap();

            assert_eq!(request.response.metadata_policy, None);
        }

        #[test]
        fn returns_oauth_error_for_unsupported_object_metadata_policy() {
            let request = Request::new(Some("{\"scope\":\"profile\"}"));

            let error = kagome::resources::metadata_policy::validate(request).unwrap_err();

            assert_eq!(error.error, "invalid_request");
            assert_eq!(
                error.error_description,
                "metadata_policy must be a json string or object"
            );
        }

        #[test]
        fn returns_oauth_error_for_invalid_json_metadata_policy() {
            let request = Request::new(Some("profile"));

            let error = kagome::resources::metadata_policy::validate(request).unwrap_err();

            assert_eq!(error.error, "invalid_request");
            assert_eq!(
                error.error_description,
                "metadata_policy must be a json string or object"
            );
        }

        #[test]
        fn returns_oauth_error_for_username_superset_metadata_policy_mismatch() {
            let request = Request::new(Some("{\"username\":{\"superset_of\":[\"username\"]}}"));

            let error = kagome::resources::metadata_policy::validate(request).unwrap_err();

            assert_eq!(error.error, "invalid_request");
            assert_eq!(
                error.error_description,
                "metadata_policy username superset_of must be contained in authorization_code chain usernames"
            );
        }
    }

    mod federated_server {
        #[test]
        fn redirects_to_configured_authorize_endpoint() {
            let request = authorize_request();
            let authorize_request = validated_authorize_request(&request);
            let federated_server = kagome::config::FederatedServerConfig {
                client_id: "kagome".to_owned(),
                client_secret: "federated_client_secret".to_owned(),
                authorize_endpoint: "https://identity.example.com/authorize".to_owned(),
                token_endpoint: "https://identity.example.com/token".to_owned(),
                endpoints: vec![kagome::config::FederatedIdentityEndpointConfig {
                    endpoint: "https://identity.example.com/userinfo".to_owned(),
                    claims: vec![kagome::config::FederatedIdentityClaimConfig {
                        claim: "sub".to_owned(),
                        target: "username".to_owned(),
                        id_token: false,
                        credential: Vec::new(),
                    }],
                }],
            };
            let authorize_request = kagome::resources::federated_server::authorize_with_server(
                authorize_request,
                &federated_server,
                "https://kagome.example.com/",
            )
            .unwrap();

            let response = authorize_request.to_response().unwrap();

            assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
            assert!(response.contains(
                "location: https://identity.example.com/authorize?response_type=code&client_id=kagome&redirect_uri=https%3A%2F%2Fkagome.example.com%2Ffederation_callback&state="
            ));
            assert!(!response.contains("<form"));
        }

        #[test]
        fn returns_not_implemented_when_federated_server_is_not_configured() {
            let request = authorize_request();
            let authorize_request = validated_authorize_request(&request);

            let response = authorize_request.to_response().unwrap();

            assert!(response.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
            assert!(response.contains("content-type: text/plain\r\n"));
            assert!(response.ends_with("\r\n\r\nnot implemented"));
            assert!(!response.contains("<form"));
        }

        fn validated_authorize_request<'a>(
            request: &'a kagome::unit::KagomeRequest,
        ) -> kagome::requests::AuthorizeLoginRequest<'a> {
            let authorize_request = kagome::requests::AuthorizeLoginRequest::from_request(request);
            let authorize_request =
                kagome::resources::response_type::validate(authorize_request).unwrap();

            kagome::resources::client_credentials::validate_with_clients(
                authorize_request,
                &crate::configured_clients(),
            )
            .unwrap()
        }

        fn authorize_request() -> kagome::unit::KagomeRequest {
            kagome::unit::KagomeRequest {
                method: "GET".to_owned(),
                path: "/authorize".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: Vec::new(),
                query_params: vec![
                    ("response_type".to_owned(), "code".to_owned()),
                    ("client_id".to_owned(), "client_id".to_owned()),
                    (
                        "redirect_uri".to_owned(),
                        "https://client.example.com/callback".to_owned(),
                    ),
                ],
                body: String::new(),
            }
        }
    }

    mod authorization_code {
        #[test]
        fn generates_cose_encrypt0_containing_client_id_and_id_token() {
            let request = token_request(Some("client_id"), Some("id_token"));
            let token_response =
                token_response_with_validated_response(&request, "client_id", "id_token");
            let generated_at = issued_at_timestamp();
            let token_response =
                kagome::resources::authorization_code::generate(token_response).unwrap();
            let authorization_code = token_response.response.authorization_code.as_ref().unwrap();

            assert_authorization_code_claims_are_not_plaintext(&authorization_code.value);
            let payload = decode_payload(&authorization_code.value);

            assert_eq!(authorization_code.payload.client_id, payload.client_id);
            assert_eq!(authorization_code.payload.id_token, payload.id_token);
            assert_eq!(authorization_code.payload.username, payload.username);
            assert_eq!(
                authorization_code.payload.previous_code,
                payload.previous_code
            );
            assert_eq!(authorization_code.payload.iat, payload.iat);
            assert_eq!(authorization_code.payload.exp, payload.exp);
            assert_eq!(
                authorization_code.expires_in,
                kagome::resources::authorization_code::AUTHORIZATION_CODE_TTL_SECONDS
            );
            assert_eq!(authorization_code.expires_in, payload.exp - payload.iat);
            assert_eq!(payload.client_id, "client_id");
            assert_eq!(payload.id_token, Some("id_token".to_owned()));
            assert_eq!(payload.username, None);
            assert_eq!(payload.previous_code, None);
            assert!(payload.iat >= generated_at);
            assert!(payload.iat <= issued_at_timestamp());
            assert_eq!(
                payload.exp,
                payload.iat + kagome::resources::authorization_code::AUTHORIZATION_CODE_TTL_SECONDS
            );
        }

        #[test]
        fn generates_authorization_code_containing_previous_code() {
            let previous_request = token_request(Some("client_id"), Some("id_token"));
            let previous_response = kagome::resources::authorization_code::generate(
                token_response_with_validated_response(&previous_request, "client_id", "id_token"),
            )
            .unwrap();
            let previous_code = previous_response
                .response
                .authorization_code
                .as_ref()
                .unwrap()
                .value
                .clone();
            let request = token_request_with_authorization_code(
                Some("client_id"),
                Some("id_token"),
                Some(&previous_code),
            );
            let mut token_response =
                continue_token_response_with_validated_response(&request, "client_id", "id_token");
            token_response.response.previous_authorization_code = Some(previous_code.clone());

            let token_response =
                kagome::resources::authorization_code::generate(token_response).unwrap();
            let authorization_code = token_response.response.authorization_code.as_ref().unwrap();
            let payload = decode_payload(&authorization_code.value);

            assert_eq!(
                authorization_code.payload.previous_code,
                Some(previous_code.clone())
            );
            assert_eq!(payload.previous_code, Some(previous_code));
        }

        #[test]
        fn validates_authorization_code_chain_at_maximum_depth() {
            let authorization_code = issue_authorization_code_chain(
                kagome::config::DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH,
            );

            let usernames = kagome::resources::authorization_code::chain_usernames(
                Some(&authorization_code),
                Some("client_id"),
            )
            .unwrap();

            assert!(usernames.is_empty());
        }

        #[test]
        fn rejects_authorization_code_generation_exceeding_maximum_depth() {
            let previous_code = issue_authorization_code_chain(
                kagome::config::DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH,
            );
            let request = token_request_with_authorization_code(
                Some("client_id"),
                Some("id_token"),
                Some(&previous_code),
            );
            let mut token_response =
                continue_token_response_with_validated_response(&request, "client_id", "id_token");
            token_response.response.previous_authorization_code = Some(previous_code);

            let error =
                kagome::resources::authorization_code::generate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(
                error.error_description,
                "authorization_code chain exceeds maximum depth"
            );
        }

        #[test]
        fn validates_authorization_code_parameter() {
            let issued_request = token_request(Some("client_id"), Some("id_token"));
            let issued_response = kagome::resources::authorization_code::generate(
                token_response_with_validated_response(&issued_request, "client_id", "id_token"),
            )
            .unwrap();
            let request = token_request_with_authorization_code(
                Some("client_id"),
                Some("id_token"),
                issued_response
                    .response
                    .authorization_code
                    .as_ref()
                    .map(|authorization_code| authorization_code.value.as_str()),
            );
            let token_response = kagome::handlers::token::CodeChainRequest::empty(&request);

            let token_response =
                kagome::resources::authorization_code::validate_optional(token_response).unwrap();

            assert_eq!(
                token_response.response.previous_authorization_code,
                issued_response
                    .response
                    .authorization_code
                    .as_ref()
                    .map(|authorization_code| authorization_code.value.clone())
            );
        }

        #[test]
        fn ignores_missing_authorization_code_parameter() {
            let request = token_request(Some("client_id"), Some("id_token"));
            let token_response = kagome::handlers::token::CodeChainRequest::empty(&request);

            let token_response =
                kagome::resources::authorization_code::validate_optional(token_response).unwrap();

            assert_eq!(token_response.response.previous_authorization_code, None);
        }

        #[test]
        fn validates_required_code_parameter_for_authorization_code_grant() {
            let issued_request = token_request(Some("client_id"), Some("id_token"));
            let issued_response = kagome::resources::authorization_code::generate(
                token_response_with_validated_response(&issued_request, "client_id", "id_token"),
            )
            .unwrap();
            let request = token_request_with_code(
                Some("client_id"),
                issued_response
                    .response
                    .authorization_code
                    .as_ref()
                    .map(|authorization_code| authorization_code.value.as_str()),
            );
            let token_response = kagome::handlers::token::AuthorizationCodeRequest::empty(&request);

            let token_response =
                kagome::resources::authorization_code::validate(token_response).unwrap();

            assert_eq!(
                token_response.response.authorization_code,
                issued_response
                    .response
                    .authorization_code
                    .as_ref()
                    .map(|authorization_code| authorization_code.value.clone())
            );
        }

        #[test]
        fn returns_oauth_error_for_missing_required_authorization_code_parameter() {
            let request = token_request(Some("client_id"), Some("id_token"));
            let token_response = kagome::handlers::token::AuthorizationCodeRequest::empty(&request);

            let error =
                kagome::resources::authorization_code::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "authorization_code is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_authorization_code_parameter() {
            let request = token_request_with_authorization_code(
                Some("client_id"),
                Some("id_token"),
                Some("app"),
            );
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                kagome::handlers::token::CodeChainRequest::empty(&request),
                &crate::configured_clients(),
            )
            .unwrap();
            let error = kagome::resources::authorization_code::validate_optional(token_response)
                .unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(
                error.error_description,
                "authorization_code must be a cose_encrypt0"
            );
        }

        #[test]
        fn rejects_oversized_authorization_code_before_decoding() {
            let oversized_code =
                "a".repeat(kagome::resources::authorization_code::MAX_AUTHORIZATION_CODE_BYTES + 1);
            let request = token_request_with_authorization_code(
                Some("client_id"),
                Some("id_token"),
                Some(&oversized_code),
            );
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                kagome::handlers::token::CodeChainRequest::empty(&request),
                &crate::configured_clients(),
            )
            .unwrap();

            let error = kagome::resources::authorization_code::validate_optional(token_response)
                .unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "authorization_code is too large");
        }

        #[test]
        fn returns_oauth_error_when_authorization_code_client_id_does_not_match_request() {
            let issued_request = token_request(Some("other_client_id"), Some("id_token"));
            let issued_response = kagome::resources::authorization_code::generate(
                token_response_with_validated_response(
                    &issued_request,
                    "other_client_id",
                    "id_token",
                ),
            )
            .unwrap();
            let request = token_request_with_authorization_code(
                Some("client_id"),
                Some("id_token"),
                issued_response
                    .response
                    .authorization_code
                    .as_ref()
                    .map(|authorization_code| authorization_code.value.as_str()),
            );
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                kagome::handlers::token::CodeChainRequest::empty(&request),
                &crate::configured_clients(),
            )
            .unwrap();
            let error = kagome::resources::authorization_code::validate_optional(token_response)
                .unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(
                error.error_description,
                "authorization_code client_id does not match request"
            );
        }

        #[test]
        fn validates_authorization_code_when_id_token_does_not_match_request() {
            let issued_request = token_request(Some("client_id"), Some("other_id_token"));
            let issued_response = kagome::resources::authorization_code::generate(
                token_response_with_validated_response(
                    &issued_request,
                    "client_id",
                    "other_id_token",
                ),
            )
            .unwrap();
            let request = token_request_with_authorization_code(
                Some("client_id"),
                Some("id_token"),
                issued_response
                    .response
                    .authorization_code
                    .as_ref()
                    .map(|authorization_code| authorization_code.value.as_str()),
            );
            let token_response = kagome::handlers::token::CodeChainRequest::empty(&request);

            let token_response =
                kagome::resources::authorization_code::validate_optional(token_response).unwrap();

            assert_eq!(
                token_response.response.previous_authorization_code,
                issued_response
                    .response
                    .authorization_code
                    .as_ref()
                    .map(|authorization_code| authorization_code.value.clone())
            );
        }

        #[test]
        fn returns_oauth_error_for_missing_client_id() {
            let request = token_request(None, Some("id_token"));
            let token_response = kagome::handlers::token::CodeChainRequest::empty(&request);
            let error =
                kagome::resources::authorization_code::generate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id is required");
        }

        #[test]
        fn returns_oauth_error_for_missing_id_token() {
            let request = token_request(Some("client_id"), None);
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                kagome::handlers::token::CodeChainRequest::empty(&request),
                &crate::configured_clients(),
            )
            .unwrap();
            let error =
                kagome::resources::authorization_code::generate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token is required");
        }

        fn decode_payload(
            authorization_code: &str,
        ) -> kagome::resources::authorization_code::AuthorizationCodeCosePayload {
            kagome::resources::authorization_code::decode_cose_payload(authorization_code).unwrap()
        }

        fn assert_authorization_code_claims_are_not_plaintext(authorization_code: &str) {
            use base64::Engine;

            let cose_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(authorization_code)
                .unwrap();

            assert!(
                !cose_bytes
                    .windows(b"client_id".len())
                    .any(|window| { window == b"client_id" })
            );
            assert!(
                !cose_bytes
                    .windows(b"id_token".len())
                    .any(|window| { window == b"id_token" })
            );
        }

        fn issued_at_timestamp() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }

        fn issue_authorization_code_chain(depth: usize) -> String {
            let mut previous_code = None;

            for _ in 0..depth {
                let request = token_request_with_authorization_code(
                    Some("client_id"),
                    Some("id_token"),
                    previous_code.as_deref(),
                );
                let mut response = continue_token_response_with_validated_response(
                    &request,
                    "client_id",
                    "id_token",
                );
                response.response.previous_authorization_code = previous_code;
                let response = kagome::resources::authorization_code::generate(response).unwrap();
                previous_code = response
                    .response
                    .authorization_code
                    .map(|authorization_code| authorization_code.value);
            }

            previous_code.expect("a non-empty chain should contain an authorization code")
        }

        fn token_request(
            client_id: Option<&str>,
            id_token: Option<&str>,
        ) -> kagome::unit::KagomeRequest {
            token_request_with_authorization_code(client_id, id_token, None)
        }

        fn token_request_with_authorization_code(
            client_id: Option<&str>,
            id_token: Option<&str>,
            authorization_code: Option<&str>,
        ) -> kagome::unit::KagomeRequest {
            let mut parameters = vec![
                "client_secret=client_secret".to_owned(),
                "grant_type=code_chain".to_owned(),
            ];
            if let Some(client_id) = client_id {
                parameters.push(format!("client_id={client_id}"));
            }
            if let Some(id_token) = id_token {
                parameters.push(format!("id_token={id_token}"));
            }
            if let Some(authorization_code) = authorization_code {
                parameters.push(format!("authorization_code={authorization_code}"));
            }

            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![kagome::unit::HttpHeader {
                    name: "content-type".to_owned(),
                    value: "application/x-www-form-urlencoded".to_owned(),
                }],
                query_params: Vec::new(),
                body: parameters.join("&"),
            }
        }

        fn token_request_with_code(
            client_id: Option<&str>,
            code: Option<&str>,
        ) -> kagome::unit::KagomeRequest {
            let mut parameters = vec![
                "client_secret=client_secret".to_owned(),
                "grant_type=authorization_code".to_owned(),
            ];
            if let Some(client_id) = client_id {
                parameters.push(format!("client_id={client_id}"));
            }
            if let Some(code) = code {
                parameters.push(format!("code={code}"));
            }

            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![kagome::unit::HttpHeader {
                    name: "content-type".to_owned(),
                    value: "application/x-www-form-urlencoded".to_owned(),
                }],
                query_params: Vec::new(),
                body: parameters.join("&"),
            }
        }

        fn token_response_with_validated_response<'a>(
            request: &'a kagome::unit::KagomeRequest,
            client_id: &str,
            id_token: &str,
        ) -> kagome::handlers::token::CodeChainRequest<'a> {
            let mut token_response = kagome::handlers::token::CodeChainRequest::empty(request);
            kagome::resources::client_credentials::Validate::add_client_credentials(
                &mut token_response,
                kagome::resources::client_credentials::ClientCredentials {
                    client_id: client_id.to_owned(),
                    client_secret: Some("client_secret".to_owned()),
                    redirect_uri: None,
                    authenticated_username: None,
                },
            );
            kagome::resources::id_token::Validate::add_id_token(&mut token_response, id_token);
            token_response
        }

        fn continue_token_response_with_validated_response<'a>(
            request: &'a kagome::unit::KagomeRequest,
            client_id: &str,
            id_token: &str,
        ) -> kagome::handlers::token::CodeChainRequest<'a> {
            let mut token_response = kagome::handlers::token::CodeChainRequest::empty(request);
            kagome::resources::client_credentials::Validate::add_client_credentials(
                &mut token_response,
                kagome::resources::client_credentials::ClientCredentials {
                    client_id: client_id.to_owned(),
                    client_secret: Some("client_secret".to_owned()),
                    redirect_uri: None,
                    authenticated_username: None,
                },
            );
            kagome::resources::id_token::Validate::add_id_token(&mut token_response, id_token);
            token_response
        }
    }

    mod client_credentials {
        #[test]
        fn validates_client_id() {
            let request = token_request(Some("client_id"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap();

            assert_eq!(
                token_response.response.client_id,
                Some("client_id".to_owned())
            );
            assert_eq!(
                token_response.response.client_secret,
                Some("client_secret".to_owned())
            );
            assert_eq!(token_response.response.grant_type, None);
        }

        #[test]
        fn returns_oauth_error_for_missing_client_id() {
            let request = token_request(None);
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_client_id() {
            let request = token_request(Some("app"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id is invalid");
        }

        #[test]
        fn rejects_grant_type_not_supported_by_client() {
            let request = token_request(Some("client_id"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let mut clients = crate::configured_clients();
            clients[0].supported_grant_types =
                vec![kagome::resources::grant_type::GrantType::AuthorizationCode];

            let error = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &clients,
            )
            .unwrap_err();

            assert_eq!(error.error, "unauthorized_client");
            assert_eq!(
                error.error_description,
                "client does not support grant_type client_credentials"
            );
        }

        #[test]
        fn rejects_combined_grant_when_one_type_is_not_supported_by_client() {
            let mut request = token_request(Some("client_id"));
            request.body = "client_id=client_id&client_secret=client_secret&grant_type=code_chain+authorization_code".to_owned();
            let token_response = kagome::handlers::token::CodeChainRequest::empty(&request);
            let mut clients = crate::configured_clients();
            clients[0].supported_grant_types =
                vec![kagome::resources::grant_type::GrantType::CodeChain];

            let error = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &clients,
            )
            .unwrap_err();

            assert_eq!(error.error, "unauthorized_client");
            assert_eq!(
                error.error_description,
                "client does not support grant_type authorization_code"
            );
        }

        #[test]
        fn rejects_response_type_not_supported_by_client() {
            let mut request = authorize_request(Some("https://client.example.com/callback"));
            request
                .query_params
                .push(("response_type".to_owned(), "token".to_owned()));
            let authorize_response =
                kagome::handlers::authorize::AuthorizeCodeRequest::from_request(&request);
            let authorize_response =
                kagome::resources::response_type::validate(authorize_response).unwrap();
            let mut clients = crate::configured_clients();
            clients[0].supported_response_types =
                vec![kagome::resources::response_type::ResponseType::Code];

            let error = kagome::resources::client_credentials::validate_with_clients(
                authorize_response,
                &clients,
            )
            .unwrap_err();

            assert_eq!(error.error, "unauthorized_client");
            assert_eq!(
                error.error_description,
                "client does not support response_type token"
            );
        }

        #[test]
        fn rejects_response_type_whose_grant_is_not_supported_by_client() {
            let mut request = authorize_request(Some("https://client.example.com/callback"));
            request
                .query_params
                .push(("response_type".to_owned(), "token".to_owned()));
            let authorize_response =
                kagome::handlers::authorize::AuthorizeCodeRequest::from_request(&request);
            let authorize_response =
                kagome::resources::response_type::validate(authorize_response).unwrap();
            let mut clients = crate::configured_clients();
            clients[0].supported_response_types =
                vec![kagome::resources::response_type::ResponseType::Token];
            clients[0].supported_grant_types =
                vec![kagome::resources::grant_type::GrantType::AuthorizationCode];

            let error = kagome::resources::client_credentials::validate_with_clients(
                authorize_response,
                &clients,
            )
            .unwrap_err();

            assert_eq!(error.error, "unauthorized_client");
            assert_eq!(
                error.error_description,
                "client does not support grant_type implicit"
            );
        }

        #[test]
        fn detects_resource_owner_credentials_in_client_id() {
            assert!(
                kagome::resources::client_credentials::client_id_resource_owner_credentials(
                    "username:password@example.com"
                )
            );

            assert!(
                !kagome::resources::client_credentials::client_id_resource_owner_credentials(
                    "username@example.com"
                )
            );

            assert!(
                !kagome::resources::client_credentials::client_id_resource_owner_credentials(
                    "username:@example.com"
                )
            );
        }

        #[test]
        fn validates_redirect_uri_for_authorize_request() {
            let request = authorize_request(Some("https://client.example.com/callback"));
            let authorize_response =
                kagome::handlers::authorize::AuthorizeCodeRequest::from_request(&request);
            let authorize_response = kagome::resources::client_credentials::validate_with_clients(
                authorize_response,
                &crate::configured_clients(),
            )
            .unwrap();

            assert_eq!(
                authorize_response.response.redirect_uri,
                Some("https://client.example.com/callback".to_owned())
            );
        }

        #[test]
        fn returns_oauth_error_for_missing_redirect_uri() {
            let request = authorize_request(None);
            let authorize_response =
                kagome::handlers::authorize::AuthorizeCodeRequest::from_request(&request);
            let error = kagome::resources::client_credentials::validate_with_clients(
                authorize_response,
                &crate::configured_clients(),
            )
            .unwrap_err();

            assert_eq!(error.error, "invalid_request");
            assert_eq!(error.error_description, "redirect_uri is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_redirect_uri() {
            let request = authorize_request(Some("https://app.example.com/callback"));
            let authorize_response =
                kagome::handlers::authorize::AuthorizeCodeRequest::from_request(&request);
            let error = kagome::resources::client_credentials::validate_with_clients(
                authorize_response,
                &crate::configured_clients(),
            )
            .unwrap_err();

            assert_eq!(error.error, "invalid_request");
            assert_eq!(error.error_description, "redirect_uri is invalid");
        }

        fn token_request(client_id: Option<&str>) -> kagome::unit::KagomeRequest {
            let mut parameters = vec![
                "client_secret=client_secret".to_owned(),
                "grant_type=client_credentials".to_owned(),
            ];
            if let Some(client_id) = client_id {
                parameters.push(format!("client_id={client_id}"));
            }

            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![kagome::unit::HttpHeader {
                    name: "content-type".to_owned(),
                    value: "application/x-www-form-urlencoded".to_owned(),
                }],
                query_params: Vec::new(),
                body: parameters.join("&"),
            }
        }

        fn authorize_request(redirect_uri: Option<&str>) -> kagome::unit::KagomeRequest {
            let mut request = authorize_request_with_client_id("client_id");
            if let Some(redirect_uri) = redirect_uri {
                request
                    .query_params
                    .push(("redirect_uri".to_owned(), redirect_uri.to_owned()));
            }

            request
        }

        fn authorize_request_with_client_id(client_id: &str) -> kagome::unit::KagomeRequest {
            kagome::unit::KagomeRequest {
                method: "GET".to_owned(),
                path: "/authorize".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: Vec::new(),
                query_params: vec![("client_id".to_owned(), client_id.to_owned())],
                body: String::new(),
            }
        }
    }

    mod client_credentials_secret {
        #[test]
        fn validates_client_secret() {
            let request = token_request(Some("client_secret"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap();

            assert_eq!(
                token_response.response.client_secret,
                Some("client_secret".to_owned())
            );
            assert_eq!(
                token_response.response.client_id,
                Some("client_id".to_owned())
            );
            assert_eq!(token_response.response.grant_type, None);
        }

        #[test]
        fn returns_oauth_error_for_missing_client_secret() {
            let request = token_request(None);
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_secret is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_client_secret() {
            let request = token_request(Some("app"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_secret is invalid");
        }

        fn token_request(client_secret: Option<&str>) -> kagome::unit::KagomeRequest {
            let mut parameters = vec![
                "client_id=client_id".to_owned(),
                "grant_type=client_credentials".to_owned(),
            ];
            if let Some(client_secret) = client_secret {
                parameters.push(format!("client_secret={client_secret}"));
            }

            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![kagome::unit::HttpHeader {
                    name: "content-type".to_owned(),
                    value: "application/x-www-form-urlencoded".to_owned(),
                }],
                query_params: Vec::new(),
                body: parameters.join("&"),
            }
        }
    }

    mod id_token {
        use std::sync::Once;

        static INITIALIZE_CONFIG: Once = Once::new();

        #[test]
        fn validates_id_token() {
            let id_token = valid_id_token();
            let request = token_request(Some(&id_token));
            let token_response = code_chain_request(&request);
            let token_response = kagome::resources::id_token::validate(token_response).unwrap();

            assert_eq!(token_response.response.id_token, Some(id_token));
            assert_eq!(
                token_response.response.client_id.as_deref(),
                Some("client_id")
            );
        }

        #[test]
        fn returns_oauth_error_for_missing_id_token() {
            let request = token_request(None);
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token is required");
        }

        #[test]
        fn returns_oauth_error_without_validated_client_context() {
            let id_token = valid_id_token();
            let request = token_request(Some(&id_token));
            let token_response = kagome::handlers::token::CodeChainRequest::empty(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_id_token() {
            let request = token_request(Some("app"));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token must be a jwt");
        }

        #[test]
        fn returns_oauth_error_for_symmetric_id_token() {
            let now = jsonwebtoken::get_current_timestamp();
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            header.jwk = Some(
                serde_json::from_value(serde_json::json!({
                    "kty": "oct",
                    "k": "c2VjcmV0",
                    "alg": "HS256"
                }))
                .unwrap(),
            );
            let id_token = jsonwebtoken::encode(
                &header,
                &serde_json::json!({"iat": now, "exp": now + 3600}),
                &jsonwebtoken::EncodingKey::from_secret(b"secret"),
            )
            .unwrap();
            let request = token_request(Some(&id_token));
            let error =
                kagome::resources::id_token::validate(code_chain_request(&request)).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token algorithm is invalid");
        }

        #[test]
        fn returns_oauth_error_for_id_token_signed_by_untrusted_key() {
            let request = token_request(Some(&id_token_signed_by_untrusted_key()));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token signing key is invalid");
        }

        #[test]
        fn returns_oauth_error_for_id_token_from_another_issuer() {
            let request = token_request(Some(&id_token_with_claim(
                "iss",
                "https://other.example.com",
            )));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token issuer is invalid");
        }

        #[test]
        fn returns_oauth_error_for_id_token_signed_with_different_key() {
            let request = token_request(Some(&id_token_signed_with_different_key()));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token signature is invalid");
        }

        #[test]
        fn returns_oauth_error_for_id_token_without_iat() {
            let request = token_request(Some(&id_token_without_iat()));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token iat is required");
        }

        #[test]
        fn returns_oauth_error_for_id_token_without_exp() {
            let request = token_request(Some(&id_token_without_exp()));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token exp is required");
        }

        #[test]
        fn returns_oauth_error_for_expired_id_token() {
            let request = token_request(Some(&expired_id_token()));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token is expired");
        }

        #[test]
        fn returns_oauth_error_for_id_token_issued_in_the_future() {
            let request = token_request(Some(&future_iat_id_token()));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(
                error.error_description,
                "id_token iat must not be in the future"
            );
        }

        #[test]
        fn returns_oauth_error_for_id_token_expiring_before_iat() {
            let request = token_request(Some(&exp_before_iat_id_token()));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token exp must be after iat");
        }

        fn code_chain_request(
            request: &kagome::unit::KagomeRequest,
        ) -> kagome::handlers::token::CodeChainRequest<'_> {
            let mut request = kagome::handlers::token::CodeChainRequest::empty(request);
            request.response.client_id = Some("client_id".to_owned());
            request
        }

        fn token_request(id_token: Option<&str>) -> kagome::unit::KagomeRequest {
            let mut parameters = vec![
                "client_id=client_id".to_owned(),
                "client_secret=client_secret".to_owned(),
                "grant_type=code_chain".to_owned(),
            ];
            if let Some(id_token) = id_token {
                parameters.push(format!("id_token={id_token}"));
            }

            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![kagome::unit::HttpHeader {
                    name: "content-type".to_owned(),
                    value: "application/x-www-form-urlencoded".to_owned(),
                }],
                query_params: Vec::new(),
                body: parameters.join("&"),
            }
        }

        fn valid_id_token() -> String {
            sign_id_token(valid_id_token_claims())
        }

        fn id_token_signed_by_untrusted_key() -> String {
            kagome::resources::crypto::sign_jwt(
                &valid_id_token_claims(),
                kagome::resources::crypto::SigningArtifact::Credential,
            )
            .unwrap()
        }

        fn id_token_signed_with_different_key() -> String {
            let token = valid_id_token();
            let (signed, signature) = token.rsplit_once('.').unwrap();
            let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
            format!("{signed}.{replacement}{}", &signature[1..])
        }

        fn id_token_without_iat() -> String {
            let mut claims = valid_id_token_claims();
            claims.as_object_mut().unwrap().remove("iat");
            sign_id_token(claims)
        }

        fn id_token_without_exp() -> String {
            let mut claims = valid_id_token_claims();
            claims.as_object_mut().unwrap().remove("exp");
            sign_id_token(claims)
        }

        fn expired_id_token() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            let mut claims = valid_id_token_claims();
            claims["iat"] = serde_json::json!(now - 7200);
            claims["exp"] = serde_json::json!(now - 3600);
            sign_id_token(claims)
        }

        fn future_iat_id_token() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            let mut claims = valid_id_token_claims();
            claims["iat"] = serde_json::json!(now + 3600);
            claims["exp"] = serde_json::json!(now + 7200);
            sign_id_token(claims)
        }

        fn exp_before_iat_id_token() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            let mut claims = valid_id_token_claims();
            claims["iat"] = serde_json::json!(now);
            claims["exp"] = serde_json::json!(now - 1);
            sign_id_token(claims)
        }

        fn id_token_with_claim(name: &str, value: &str) -> String {
            let mut claims = valid_id_token_claims();
            claims[name] = serde_json::json!(value);
            sign_id_token(claims)
        }

        fn valid_id_token_claims() -> serde_json::Value {
            INITIALIZE_CONFIG.call_once(|| {
                let config = kagome::config::Config::load_from_path(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/kagome.yaml"
                ))
                .expect("test configuration should load");
                kagome::config::Config::set_global(config)
                    .expect("test configuration should initialize");
            });
            let now = jsonwebtoken::get_current_timestamp();
            serde_json::json!({
                "iss": kagome::config::Config::global().server.issuer,
                "sub": "username",
                "aud": "client_id",
                "client_id": "client_id",
                "username": "username",
                "profile": {"username": "username"},
                "iat": now,
                "exp": now + 3600,
            })
        }

        fn sign_id_token(claims: serde_json::Value) -> String {
            kagome::resources::crypto::sign_jwt(
                &claims,
                kagome::resources::crypto::SigningArtifact::IdToken,
            )
            .unwrap()
        }
    }

    mod grant_type {
        #[test]
        fn validates_client_credentials() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();

            assert_eq!(
                token_response.response.grant_type,
                Some(kagome::resources::grant_type::GrantType::ClientCredentials)
            );
        }

        #[test]
        fn validates_resource_owner_password_credentials() {
            let request = token_request(Some("password"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();

            assert_eq!(
                token_response.response.grant_type,
                Some(kagome::resources::grant_type::GrantType::ResourceOwnerPasswordCredentials)
            );
        }

        #[test]
        fn validates_code_chain() {
            let request = token_request(Some("code_chain"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();

            assert_eq!(
                token_response.response.grant_type,
                Some(kagome::resources::grant_type::GrantType::CodeChain)
            );
        }

        #[test]
        fn validates_code_chain_authorization_code() {
            let request = token_request(Some("code_chain authorization_code"));
            let token_response = kagome::handlers::token::GrantTypeRequest::from_request(&request);
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();

            assert_eq!(
                token_response.response.grant_type,
                Some(kagome::resources::grant_type::GrantType::CodeChain)
            );
            assert_eq!(
                token_response.response.grant_types,
                vec![
                    kagome::resources::grant_type::GrantType::CodeChain,
                    kagome::resources::grant_type::GrantType::AuthorizationCode,
                ]
            );
        }

        #[test]
        fn validates_authorization_code() {
            let request = token_request(Some("authorization_code"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();

            assert_eq!(
                token_response.response.grant_type,
                Some(kagome::resources::grant_type::GrantType::AuthorizationCode)
            );
        }

        #[test]
        fn converts_validated_token_response_to_response() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap();
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();
            let token_response = kagome::resources::access_token::generate(token_response).unwrap();

            let response = token_response.to_response().unwrap();

            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(response.contains("content-type: application/json\r\n"));
            assert!(response.contains("connection: close\r\n"));
            assert!(response.contains("\"token_type\":\"bearer\""));
            assert!(response.contains("\"access_token\":\""));
            assert!(response.contains("\"expires_in\":3600"));
            assert!(!response.contains("\"client_id\""));
            assert!(!response.contains("\"client_secret\""));
            assert!(!response.contains("\"grant_type\""));
        }

        #[test]
        fn returns_oauth_error_when_token_response_has_no_access_token() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap();
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();

            let error = token_response.to_response().unwrap_err();

            assert_eq!(error.error, "invalid_token_response");
            assert_eq!(
                error.error_description,
                "token response requires access_token"
            );
        }

        #[test]
        fn converts_empty_authorization_code_response_to_oauth_error() {
            let request = token_request(Some("authorization_code"));
            let token_response = kagome::handlers::token::AuthorizationCodeRequest::empty(&request);
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();

            let error = token_response.to_response().unwrap_err();

            assert_eq!(error.error, "invalid_token_response");
            assert_eq!(
                error.error_description,
                "token response requires access_token"
            );
        }

        #[test]
        fn converts_token_response_with_no_client_id_to_response() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();

            let error = kagome::resources::access_token::generate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id is required");
        }

        #[test]
        fn converts_token_response_with_no_client_secret_to_response() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap();
            let token_response = kagome::resources::grant_type::validate(token_response).unwrap();
            let token_response = kagome::resources::access_token::generate(token_response).unwrap();

            let response = token_response.to_response().unwrap();

            assert!(response.contains("\"token_type\":\"bearer\""));
            assert!(response.contains("\"access_token\":\""));
            assert!(response.contains("\"expires_in\":3600"));
        }

        #[test]
        fn converts_token_response_with_no_grant_type_to_response() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response = kagome::resources::client_credentials::validate_with_clients(
                token_response,
                &crate::configured_clients(),
            )
            .unwrap();
            let token_response = kagome::resources::access_token::generate(token_response).unwrap();

            let response = token_response.to_response().unwrap();

            assert!(response.contains("\"token_type\":\"bearer\""));
            assert!(response.contains("\"access_token\":\""));
            assert!(response.contains("\"expires_in\":3600"));
        }

        #[test]
        fn returns_oauth_error_for_missing_grant_type() {
            let request = token_request(None);
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error = kagome::resources::grant_type::validate(token_response).unwrap_err();

            assert_eq!(error.error, "unsupported_grant_type");
            assert_eq!(
                error.error_description,
                "grant_type must be one of: client_credentials, password, code_chain, authorization_code, urn:ietf:params:oauth:grant-type:pre-authorized_code"
            );
        }

        #[test]
        fn returns_oauth_error_for_unsupported_grant_type() {
            let request = token_request(Some("refresh_token"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error = kagome::resources::grant_type::validate(token_response).unwrap_err();

            assert_eq!(error.error, "unsupported_grant_type");
            assert_eq!(
                error.error_description,
                "grant_type must be one of: client_credentials, password, code_chain, authorization_code, urn:ietf:params:oauth:grant-type:pre-authorized_code"
            );
        }

        fn token_request(grant_type: Option<&str>) -> kagome::unit::KagomeRequest {
            let mut parameters = vec![
                "client_id=client_id".to_owned(),
                "client_secret=client_secret".to_owned(),
            ];
            if let Some(grant_type) = grant_type {
                parameters.push(format!("grant_type={grant_type}"));
            }

            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![kagome::unit::HttpHeader {
                    name: "content-type".to_owned(),
                    value: "application/x-www-form-urlencoded".to_owned(),
                }],
                query_params: Vec::new(),
                body: parameters.join("&"),
            }
        }
    }
}
