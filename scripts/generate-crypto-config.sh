#!/bin/sh
set -eu

output=${1:-kagome.crypto.yaml}

if [ -e "$output" ]; then
    echo "refusing to overwrite existing crypto configuration: $output" >&2
    exit 1
fi

temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

credential_private_key="$temporary_directory/credential.pem"
id_token_private_key="$temporary_directory/id-token.pem"
request_private_key="$temporary_directory/request.pem"

openssl genpkey -algorithm Ed25519 -out "$credential_private_key"
openssl genpkey -algorithm Ed25519 -out "$id_token_private_key"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$request_private_key"

base64url() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

ed25519_x() {
    openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | tail -c 32 | base64url
}

request_public_key="$temporary_directory/request-public.bin"
openssl pkey -in "$request_private_key" -pubout -outform DER 2>/dev/null \
    | tail -c 65 > "$request_public_key"
request_x=$(dd if="$request_public_key" bs=1 skip=1 count=32 2>/dev/null | base64url)
request_y=$(dd if="$request_public_key" bs=1 skip=33 count=32 2>/dev/null | base64url)
credential_x=$(ed25519_x "$credential_private_key")
id_token_x=$(ed25519_x "$id_token_private_key")

indent_key() {
    sed 's/^/      /' "$1"
}

umask 077
{
    echo "encryption:"
    echo "  access_token: $(openssl rand -hex 32)"
    echo "  authorization_code: $(openssl rand -hex 32)"
    echo "  credential_access_token: $(openssl rand -hex 32)"
    echo "  federation_state: $(openssl rand -hex 32)"
    echo "  pre_authorized_code: $(openssl rand -hex 32)"
    echo "  presentation_state: $(openssl rand -hex 32)"
    echo "  siopv2_state: $(openssl rand -hex 32)"
    echo "signing:"
    echo "  credential:"
    echo "    private_key: |-"
    indent_key "$credential_private_key"
    echo "    public_jwk:"
    echo "      kty: OKP"
    echo "      crv: Ed25519"
    echo "      alg: EdDSA"
    echo "      use: sig"
    echo "      kid: kagome-credential-signing-key"
    echo "      x: $credential_x"
    echo "  id_token:"
    echo "    private_key: |-"
    indent_key "$id_token_private_key"
    echo "    public_jwk:"
    echo "      kty: OKP"
    echo "      crv: Ed25519"
    echo "      alg: EdDSA"
    echo "      use: sig"
    echo "      kid: kagome-id-token-signing-key"
    echo "      x: $id_token_x"
    echo "  request_object:"
    echo "    private_key: |-"
    indent_key "$request_private_key"
    echo "    public_jwk:"
    echo "      kty: EC"
    echo "      crv: P-256"
    echo "      alg: ES256"
    echo "      use: sig"
    echo "      kid: kagome-request-signing-key"
    echo "      x: $request_x"
    echo "      y: $request_y"
} > "$output"

echo "generated $output"
