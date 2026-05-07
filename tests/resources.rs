mod resources {
    mod access_token {
        #[test]
        fn generates_hs512_jwt_containing_client_id() {
            let request = token_request(Some("client_id"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let generated_at = issued_at_timestamp();
            let token_response =
                kagome::resources::access_token::generate(token_response, &request).unwrap();
            let access_token = token_response.access_token.as_ref().unwrap();

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
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let error =
                kagome::resources::access_token::generate(token_response, &request).unwrap_err();

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
            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![],
                client_id: client_id.map(str::to_owned),
                client_secret: Some("client_secret".to_owned()),
                grant_type: Some("client_credentials".to_owned()),
                body: "".to_owned(),
            }
        }
    }

    mod client_id {
        #[test]
        fn validates_client_id() {
            let request = token_request(Some("client_id"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let token_response =
                kagome::resources::client_id::validate(token_response, &request).unwrap();

            assert_eq!(token_response.client_id, Some("client_id".to_owned()));
            assert_eq!(token_response.grant_type, None);
        }

        #[test]
        fn returns_oauth_error_for_missing_client_id() {
            let request = token_request(None);
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let error =
                kagome::resources::client_id::validate(token_response, &request).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_client_id() {
            let request = token_request(Some("app"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let error =
                kagome::resources::client_id::validate(token_response, &request).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_id must be: client_id");
        }

        fn token_request(client_id: Option<&str>) -> kagome::unit::KagomeRequest {
            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![],
                client_id: client_id.map(str::to_owned),
                client_secret: Some("client_secret".to_owned()),
                grant_type: Some("client_credentials".to_owned()),
                body: "".to_owned(),
            }
        }
    }

    mod client_secret {
        #[test]
        fn validates_client_secret() {
            let request = token_request(Some("client_secret"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let token_response =
                kagome::resources::client_secret::validate(token_response, &request).unwrap();

            assert_eq!(
                token_response.client_secret,
                Some("client_secret".to_owned())
            );
            assert_eq!(token_response.client_id, None);
            assert_eq!(token_response.grant_type, None);
        }

        #[test]
        fn returns_oauth_error_for_missing_client_secret() {
            let request = token_request(None);
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let error =
                kagome::resources::client_secret::validate(token_response, &request).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(error.error_description, "client_secret is required");
        }

        #[test]
        fn returns_oauth_error_for_invalid_client_secret() {
            let request = token_request(Some("app"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let error =
                kagome::resources::client_secret::validate(token_response, &request).unwrap_err();

            assert_eq!(error.error, "invalid_client");
            assert_eq!(
                error.error_description,
                "client_secret must be: client_secret"
            );
        }

        fn token_request(client_secret: Option<&str>) -> kagome::unit::KagomeRequest {
            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![],
                client_id: Some("client_id".to_owned()),
                client_secret: client_secret.map(str::to_owned),
                grant_type: Some("client_credentials".to_owned()),
                body: "".to_owned(),
            }
        }
    }

    mod grant_type {
        #[test]
        fn validates_client_credentials() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let token_response =
                kagome::resources::grant_type::validate(token_response, &request).unwrap();

            assert_eq!(
                token_response.grant_type,
                Some(kagome::resources::grant_type::GrantType::ClientCredentials)
            );
        }

        #[test]
        fn converts_validated_token_response_to_response() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let token_response =
                kagome::resources::client_id::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::client_secret::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::grant_type::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::access_token::generate(token_response, &request).unwrap();

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
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let token_response =
                kagome::resources::client_id::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::client_secret::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::grant_type::validate(token_response, &request).unwrap();

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
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let token_response =
                kagome::resources::grant_type::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::access_token::generate(token_response, &request).unwrap();

            let response = token_response.to_response().unwrap();

            assert!(response.contains("\"token_type\":\"bearer\""));
            assert!(response.contains("\"access_token\":\""));
            assert!(response.contains("\"expires_in\":3600"));
        }

        #[test]
        fn converts_token_response_with_no_client_secret_to_response() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let token_response =
                kagome::resources::client_id::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::grant_type::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::access_token::generate(token_response, &request).unwrap();

            let response = token_response.to_response().unwrap();

            assert!(response.contains("\"token_type\":\"bearer\""));
            assert!(response.contains("\"access_token\":\""));
            assert!(response.contains("\"expires_in\":3600"));
        }

        #[test]
        fn converts_token_response_with_no_grant_type_to_response() {
            let request = token_request(Some("client_credentials"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let token_response =
                kagome::resources::client_id::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::client_secret::validate(token_response, &request).unwrap();
            let token_response =
                kagome::resources::access_token::generate(token_response, &request).unwrap();

            let response = token_response.to_response().unwrap();

            assert!(response.contains("\"token_type\":\"bearer\""));
            assert!(response.contains("\"access_token\":\""));
            assert!(response.contains("\"expires_in\":3600"));
        }

        #[test]
        fn returns_oauth_error_for_missing_grant_type() {
            let request = token_request(None);
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let error =
                kagome::resources::grant_type::validate(token_response, &request).unwrap_err();

            assert_eq!(error.error, "unsupported_grant_type");
            assert_eq!(
                error.error_description,
                "grant_type must be one of: client_credentials"
            );
        }

        #[test]
        fn returns_oauth_error_for_unsupported_grant_type() {
            let request = token_request(Some("password"));
            let token_response = kagome::handlers::token::TokenResponse::empty();
            let error =
                kagome::resources::grant_type::validate(token_response, &request).unwrap_err();

            assert_eq!(error.error, "unsupported_grant_type");
            assert_eq!(
                error.error_description,
                "grant_type must be one of: client_credentials"
            );
        }

        fn token_request(grant_type: Option<&str>) -> kagome::unit::KagomeRequest {
            kagome::unit::KagomeRequest {
                method: "POST".to_owned(),
                path: "/token".to_owned(),
                protocol: "HTTP/1.1".to_owned(),
                headers: vec![],
                client_id: Some("client_id".to_owned()),
                client_secret: Some("client_secret".to_owned()),
                grant_type: grant_type.map(str::to_owned),
                body: "".to_owned(),
            }
        }
    }
}
