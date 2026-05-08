# kagome

## Agentic Chat

Run the agentic chat script through Docker Compose with:

```bash
docker compose --profile tools run --rm agentic-chat
```

The script keeps a simple agentic workflow where a planner creates a plan, a
critic reviews it, and a writer produces the final reply locally.

Each agent has its own signing key. When an agent receives a message, it signs
an `id_token` and calls the local `/token` endpoint with the `code_chain` grant
before processing that message.

Optional environment variables:

```bash
KAGOME_TOKEN_TARGET=http://kagome:4000/token
KAGOME_CLIENT_ID=client_id
KAGOME_CLIENT_SECRET=client_secret
KAGOME_TOKEN_TIMEOUT=5
```
