mod resources {
    mod access_token {
        #[test]
        fn generates_hs512_jwt_containing_client_id() {
            let request = token_request(Some("client_id"));
            let mut token_response =
                kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            kagome::resources::client_credentials::Validate::add_client_credentials(
                &mut token_response,
                kagome::resources::client_credentials::ClientCredentials {
                    client_id: "client_id".to_owned(),
                    client_secret: Some("client_secret".to_owned()),
                    redirect_uri: None,
                },
            );
            let generated_at = issued_at_timestamp();
            let token_response = kagome::resources::access_token::generate(token_response).unwrap();
            let access_token = token_response.response.access_token.as_ref().unwrap();

            let payload = decode_payload(&access_token.value);

            assert_eq!(
                payload.token_type,
                kagome::resources::access_token::TOKEN_TYPE
            );
            assert_eq!(access_token.payload.token_type, payload.token_type);
            assert_eq!(access_token.payload.client_id, payload.client_id);
            assert_eq!(access_token.payload.iat, payload.iat);
            assert_eq!(access_token.payload.exp, payload.exp);
            assert_eq!(
                access_token.expires_in,
                kagome::resources::access_token::ACCESS_TOKEN_TTL_SECONDS
            );
            assert_eq!(access_token.expires_in, payload.exp - payload.iat);
            assert_eq!(payload.client_id, "client_id");
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
        ) -> kagome::resources::access_token::AccessTokenJwtPayload {
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS512);
            validation.validate_exp = false;
            validation.required_spec_claims.clear();

            jsonwebtoken::decode::<kagome::resources::access_token::AccessTokenJwtPayload>(
                access_token,
                &jsonwebtoken::DecodingKey::from_secret(
                    kagome::resources::access_token::SECRET.as_bytes(),
                ),
                &validation,
            )
            .unwrap()
            .claims
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
            let request = token_request_with_authorization_code(
                Some("client_id"),
                Some("id_token"),
                Some("previous.cose.code"),
            );
            let mut token_response =
                continue_token_response_with_validated_response(&request, "client_id", "id_token");
            token_response.response.previous_authorization_code =
                Some("previous.cose.code".to_owned());

            let token_response =
                kagome::resources::authorization_code::generate(token_response).unwrap();
            let authorization_code = token_response.response.authorization_code.as_ref().unwrap();
            let payload = decode_payload(&authorization_code.value);

            assert_eq!(
                authorization_code.payload.previous_code,
                Some("previous.cose.code".to_owned())
            );
            assert_eq!(payload.previous_code, Some("previous.cose.code".to_owned()));
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
        fn validates_required_authorization_code_parameter() {
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
            let token_response = kagome::resources::client_credentials::validate(
                kagome::handlers::token::CodeChainRequest::empty(&request),
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
            let token_response = kagome::resources::client_credentials::validate(
                kagome::handlers::token::CodeChainRequest::empty(&request),
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
            let token_response = kagome::resources::client_credentials::validate(
                kagome::handlers::token::CodeChainRequest::empty(&request),
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
            let token_response =
                kagome::resources::client_credentials::validate(token_response).unwrap();

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
            let error =
                kagome::resources::client_credentials::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_client_id() {
            let request = token_request(Some("app"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error =
                kagome::resources::client_credentials::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id must be: client_id");
        }

        #[test]
        fn validates_redirect_uri_for_authorize_request() {
            let request =
                authorize_request(Some(kagome::resources::client_credentials::REDIRECT_URI));
            let authorize_response =
                kagome::handlers::authorize::AuthorizeCodeRequest::from_request(&request);
            let authorize_response =
                kagome::resources::client_credentials::validate(authorize_response).unwrap();

            assert_eq!(
                authorize_response.response.redirect_uri,
                Some(kagome::resources::client_credentials::REDIRECT_URI.to_owned())
            );
        }

        #[test]
        fn returns_oauth_error_for_missing_redirect_uri() {
            let request = authorize_request(None);
            let authorize_response =
                kagome::handlers::authorize::AuthorizeCodeRequest::from_request(&request);
            let error =
                kagome::resources::client_credentials::validate(authorize_response).unwrap_err();

            assert_eq!(error.error, "invalid_request");
            assert_eq!(error.error_description, "redirect_uri is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_redirect_uri() {
            let request = authorize_request(Some("https://app.example.com/callback"));
            let authorize_response =
                kagome::handlers::authorize::AuthorizeCodeRequest::from_request(&request);
            let error =
                kagome::resources::client_credentials::validate(authorize_response).unwrap_err();

            assert_eq!(error.error, "invalid_request");
            assert_eq!(
                error.error_description,
                "redirect_uri must be: https://client.example.com/callback"
            );
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
            let mut query_params = vec![("client_id".to_owned(), "client_id".to_owned())];
            if let Some(redirect_uri) = redirect_uri {
                query_params.push(("redirect_uri".to_owned(), redirect_uri.to_owned()));
            }

            kagome::unit::KagomeRequest {
                method: "GET".to_owned(),
                path: "/authorize".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: Vec::new(),
                query_params,
                body: String::new(),
            }
        }
    }

    mod client_credentials_secret {
        #[test]
        fn validates_client_secret() {
            let request = token_request(Some("client_secret"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let token_response =
                kagome::resources::client_credentials::validate(token_response).unwrap();

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
            let error =
                kagome::resources::client_credentials::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_secret is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_client_secret() {
            let request = token_request(Some("app"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error =
                kagome::resources::client_credentials::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(
                error.error_description,
                "client_secret must be: client_secret"
            );
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
        #[test]
        fn validates_id_token() {
            let id_token = valid_id_token();
            let request = token_request(Some(&id_token));
            let token_response = code_chain_request(&request);
            let token_response = kagome::resources::id_token::validate(token_response).unwrap();

            assert_eq!(token_response.response.id_token, Some(id_token));
            assert_eq!(token_response.response.client_id, None);
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
        fn returns_oauth_error_for_invalid_id_token() {
            let request = token_request(Some("app"));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token must be a jwt");
        }

        #[test]
        fn returns_oauth_error_for_id_token_without_jwk_header() {
            let request = token_request(Some(&id_token_without_jwk_header()));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token header must include jwk");
        }

        #[test]
        fn returns_oauth_error_for_id_token_with_invalid_jwk_header() {
            let request = token_request(Some(&id_token_with_invalid_jwk_header()));
            let token_response = code_chain_request(&request);
            let error = kagome::resources::id_token::validate(token_response).unwrap_err();

            assert_eq!(error.error, "invalid_grant");
            assert_eq!(error.error_description, "id_token jwk must be valid");
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
            kagome::handlers::token::CodeChainRequest::empty(request)
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
            let now = jsonwebtoken::get_current_timestamp();
            encode_id_token("secret", Some(jwk()), Some(now), Some(now + 3600))
        }

        fn id_token_without_jwk_header() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            encode_id_token("secret", None, Some(now), Some(now + 3600))
        }

        fn id_token_with_invalid_jwk_header() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            encode_id_token("secret", Some(invalid_jwk()), Some(now), Some(now + 3600))
        }

        fn id_token_signed_with_different_key() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            encode_id_token("other", Some(jwk()), Some(now), Some(now + 3600))
        }

        fn id_token_without_iat() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            encode_id_token("secret", Some(jwk()), None, Some(now + 3600))
        }

        fn id_token_without_exp() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            encode_id_token("secret", Some(jwk()), Some(now), None)
        }

        fn expired_id_token() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            encode_id_token("secret", Some(jwk()), Some(now - 7200), Some(now - 3600))
        }

        fn future_iat_id_token() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            encode_id_token("secret", Some(jwk()), Some(now + 3600), Some(now + 7200))
        }

        fn exp_before_iat_id_token() -> String {
            let now = jsonwebtoken::get_current_timestamp();
            encode_id_token("secret", Some(jwk()), Some(now), Some(now - 1))
        }

        fn encode_id_token(
            secret: &str,
            jwk: Option<jsonwebtoken::jwk::Jwk>,
            iat: Option<u64>,
            exp: Option<u64>,
        ) -> String {
            #[derive(serde::Serialize)]
            struct Claims {
                #[serde(skip_serializing_if = "Option::is_none")]
                iat: Option<u64>,
                #[serde(skip_serializing_if = "Option::is_none")]
                exp: Option<u64>,
            }

            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            header.jwk = jwk;

            jsonwebtoken::encode(
                &header,
                &Claims { iat, exp },
                &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
            )
            .unwrap()
        }

        fn jwk() -> jsonwebtoken::jwk::Jwk {
            jsonwebtoken::jwk::Jwk {
                common: jsonwebtoken::jwk::CommonParameters {
                    key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::HS256),
                    ..Default::default()
                },
                algorithm: jsonwebtoken::jwk::AlgorithmParameters::OctetKey(
                    jsonwebtoken::jwk::OctetKeyParameters {
                        key_type: jsonwebtoken::jwk::OctetKeyType::Octet,
                        value: "c2VjcmV0".to_owned(),
                    },
                ),
            }
        }

        fn invalid_jwk() -> jsonwebtoken::jwk::Jwk {
            jsonwebtoken::jwk::Jwk {
                common: jsonwebtoken::jwk::CommonParameters {
                    key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::HS256),
                    ..Default::default()
                },
                algorithm: jsonwebtoken::jwk::AlgorithmParameters::OctetKey(
                    jsonwebtoken::jwk::OctetKeyParameters {
                        key_type: jsonwebtoken::jwk::OctetKeyType::Octet,
                        value: "not-base64".to_owned(),
                    },
                ),
            }
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
            let token_response =
                kagome::resources::client_credentials::validate(token_response).unwrap();
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
            let token_response =
                kagome::resources::client_credentials::validate(token_response).unwrap();
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
            let token_response =
                kagome::resources::client_credentials::validate(token_response).unwrap();
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
            let token_response =
                kagome::resources::client_credentials::validate(token_response).unwrap();
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
                "grant_type must be one of: client_credentials, code_chain, authorization_code"
            );
        }

        #[test]
        fn returns_oauth_error_for_unsupported_grant_type() {
            let request = token_request(Some("password"));
            let token_response = kagome::handlers::token::ClientCredentialsRequest::empty(&request);
            let error = kagome::resources::grant_type::validate(token_response).unwrap_err();

            assert_eq!(error.error, "unsupported_grant_type");
            assert_eq!(
                error.error_description,
                "grant_type must be one of: client_credentials, code_chain, authorization_code"
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
