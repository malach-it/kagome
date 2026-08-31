# kagome

Proof of concept of OAuth 2.0 and satellite specifications implementation in
Rust

## Agentic Chat

Run the agentic chat script through Docker Compose with:

```bash
docker compose --profile tools run --rm agentic-chat
```

The script keeps a simple agentic workflow where a planner creates a plan, a
critic reviews it, and a writer produces the final reply locally.

Each agent has its own signing key. When an agent receives a message, it signs
an `id_token` and calls the local `/token` endpoint with the `code_chain` grant
before processing that message. The `id_token` remains a JWT, while issued
authorization codes are COSE_Mac0 values.

Optional environment variables:

```bash
KAGOME_TOKEN_TARGET=http://kagome:4000/token
KAGOME_CLIENT_ID=client_id
KAGOME_CLIENT_SECRET=client_secret
KAGOME_TOKEN_TIMEOUT=5
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
