# Kagome

## Docker

The bundled Boruta gateway configuration requires these environment variables at
container startup:

- `BORUTA_GATEWAY_ALIASES`: aliases encoded as a YAML or JSON array. Use `[]` if
  the gateway has no aliases.
- `BORUTA_GATEWAY_VIRTUAL_HOST`: virtual host used by the microgateway.
- `PORT`: port exposed by the Boruta HTTPS sidecar. Defaults to `8044`.

For example:

```sh
docker build -t kagome .
docker run --rm \
  -e KAGOME_SERVER_ADDRESS=0.0.0.0:4000 \
  -e 'BORUTA_GATEWAY_ALIASES=["kagome.internal","kagome.example.com"]' \
  -e BORUTA_GATEWAY_VIRTUAL_HOST=kagome.example.com \
  -e PORT=8044 \
  -p 8044:8044 \
  kagome
```

The container renders these values into `/etc/boruta/gateway.yml` before the
Kagome and Boruta processes start. `BORUTA_GATEWAY_ALIASES` and
`BORUTA_GATEWAY_VIRTUAL_HOST` must be non-empty,
`BORUTA_GATEWAY_ALIASES` must use array syntax, and `PORT` must be an integer
between 1 and 65535. It controls the internal HTTPS sidecar listener; Kagome
remains available only to the sidecar on port 4000.
