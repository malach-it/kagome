# Kagome

## Docker

The bundled Boruta gateway configuration requires these environment variables at
container startup:

- `BORUTA_GATEWAY_ALIASES`: aliases encoded as a YAML or JSON array. Use `[]` if
  the gateway has no aliases.
- `BORUTA_GATEWAY_VIRTUAL_HOST`: virtual host used by the microgateway.

For example:

```sh
docker build -t kagome .
docker run --rm \
  -e KAGOME_SERVER_ADDRESS=0.0.0.0:4000 \
  -e 'BORUTA_GATEWAY_ALIASES=["kagome.internal","kagome.example.com"]' \
  -e BORUTA_GATEWAY_VIRTUAL_HOST=kagome.example.com \
  -p 4000:4000 \
  kagome
```

The container renders these values into `/etc/boruta/gateway.yml` before the
Kagome and Boruta processes start. Both variables must be non-empty, and
`BORUTA_GATEWAY_ALIASES` must use array syntax.
