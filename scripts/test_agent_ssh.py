#!/usr/bin/env python3
"""Send a signed SSH scope registration to a running Kagome server."""

import argparse
import base64
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
from urllib.parse import urlsplit

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import yaml


REPOSITORY = Path(__file__).resolve().parents[1]
DEFAULT_PROVIDER_KEY = Path(".agent-keys/example-provider-ed25519.pem")
DEFAULT_AGENT_KEY = Path(".agent-keys/agent-ed25519")
RESOURCE_PATH = "/agent/resource"
AGENT_TOKEN_PATH = "/agent-token"


def b64url(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def json64(value):
    return b64url(json.dumps(value, separators=(",", ":")).encode())


def public_key_x(key):
    return b64url(key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ))


def sign_agent_token(provider, issuer, kid, subject, agent):
    now = int(time.time())
    header = json64({"typ": "aa-agent+jwt", "alg": "Ed25519", "kid": kid})
    claims = json64({
        "iss": issuer,
        "sub": subject,
        "dwk": "aauth-agent.json",
        "jti": f"agent-ssh-e2e-{public_key_x(agent)}",
        "iat": now - 1,
        "exp": now + 100,
        "cnf": {"jwk": {
            "alg": "Ed25519", "kty": "OKP", "crv": "Ed25519", "x": public_key_x(agent),
        }},
    })
    message = f"{header}.{claims}"
    return f"{message}.{b64url(provider.sign(message.encode()))}"


def signed_headers(authority, path, agent, signature_key, scope=None):
    components = {
        "@method": "POST", "@authority": authority, "@path": path,
        "signature-key": signature_key,
    }
    headers = {"Host": authority, "Signature-Key": signature_key}
    if scope is not None:
        headers["SSH-Scope"] = components["ssh-scope"] = scope
    covered = " ".join(f'"{name}"' for name in components)
    params = f"({covered});created={int(time.time())}"
    lines = [f'"{name}": {value}' for name, value in components.items()]
    lines.append(f'"@signature-params": {params}')
    payload = "\n".join(lines)
    proof = base64.b64encode(agent.sign(payload.encode())).decode()
    headers.update({"Signature-Input": f"sig={params}", "Signature": f"sig=:{proof}:"})
    return headers


def provider_kid(config, provider, issuer):
    public_x = public_key_x(provider)
    matches = [
        (entry["issuer"], key["kid"])
        for entry in config.get("agent_providers", [])
        for key in (entry.get("jwks") or {}).get("keys", [])
        if key.get("alg") == "Ed25519" and key.get("x") == public_x
    ]
    for pinned_issuer, kid in matches:
        if pinned_issuer == issuer:
            return kid
    if matches:
        pinned_issuers = ", ".join(dict.fromkeys(pinned_issuer for pinned_issuer, _ in matches))
        raise SystemExit(
            f"The provider key is pinned under {pinned_issuers}, but the SSH resource expects {issuer}. "
            "Use --provider-url for the configured provider, or configure the SSH resource "
            "with the local provider's issuer and agent subject."
        )
    raise SystemExit(f"The provider key does not match an Ed25519 JWK pinned for {issuer} in kagome.yaml.")


def request_target(url, path):
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid URL: {error}") from error
    if (
        parsed.scheme not in ("http", "https") or not host or port == 0
        or parsed.username is not None or parsed.fragment or parsed.path != path
    ):
        raise argparse.ArgumentTypeError(f"use an HTTP or HTTPS URL ending in {path}")
    authority = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    return url, authority


def curl_command(url, headers, *, include_headers=False):
    args = [
        "curl", "--disable", "--globoff", "--request", "POST", "--url", url,
        "--silent", "--show-error", "--fail-with-body", "--max-time", "10",
    ]
    if include_headers:
        args.append("--include")
    for name, value in headers.items():
        args.extend(("--header", f"{name}: {value}"))
    return args


def request_agent_token(provider_url, agent):
    endpoint = provider_url.rstrip("/")
    if not endpoint.endswith(AGENT_TOKEN_PATH):
        endpoint += AGENT_TOKEN_PATH
    url, authority = request_target(endpoint, AGENT_TOKEN_PATH)
    parsed = urlsplit(url)
    if parsed.query or (parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1")):
        raise argparse.ArgumentTypeError("--provider-url requires HTTPS, or HTTP on loopback")

    signature_key = f'sig=hwk;kty="OKP";crv="Ed25519";x="{public_key_x(agent)}";alg="Ed25519"'
    headers = signed_headers(authority, AGENT_TOKEN_PATH, agent, signature_key)
    response = subprocess.run(curl_command(url, headers), capture_output=True, text=True)
    if response.returncode:
        raise argparse.ArgumentTypeError(f"agent token request failed: {response.stderr.strip()}")
    try:
        token = json.loads(response.stdout)["agent_token"]
    except (ValueError, TypeError, KeyError):
        token = None
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}", token):
        raise argparse.ArgumentTypeError("the provider did not return a valid agent token")
    return token


def load_private_key(path, role):
    try:
        data = path.read_bytes()
    except OSError as error:
        raise argparse.ArgumentTypeError(f"cannot read {role} key {path}: {error.strerror}") from error

    try:
        if data.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
            key = serialization.load_ssh_private_key(data, password=None)
        else:
            key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as error:
        raise argparse.ArgumentTypeError(
            f"cannot load {path}; supply an unencrypted Ed25519 {role} key in PEM or OpenSSH format"
        ) from error
    if not isinstance(key, Ed25519PrivateKey):
        raise argparse.ArgumentTypeError(
            f"{path} is not an Ed25519 key; supply an Ed25519 {role} key"
        )
    return key


def configured_registration_command(provider_key=None, agent_key=None, provider_url=None,
                                    scopes=None, resource_url=None, *, include_headers=True):
    config = yaml.safe_load((REPOSITORY / "kagome.yaml").read_text())
    policy = config.get("ssh_resource", config.get("agent_ssh"))
    if policy is None:
        raise argparse.ArgumentTypeError("configure ssh_resource in kagome.yaml before registering an SSH scope")
    url = resource_url or config["server"]["issuer"].rstrip("/") + RESOURCE_PATH
    url, authority = request_target(url, RESOURCE_PATH)
    if scopes is None:
        scopes = list(policy.get("scopes", []))
        if policy.get("executable"):
            scopes = ["resource"]
        elif len(scopes) != 1:
            raise argparse.ArgumentTypeError("specify --scope when there is no single configured SSH scope")
    if any(not scope or any(not 0x21 <= ord(ch) <= 0x7E or ch in '\"\\' for ch in scope)
           for scope in scopes) or len(scopes) != len(set(scopes)):
        raise argparse.ArgumentTypeError("each --scope must be a unique, valid OAuth scope token")
    if provider_url is not None:
        agent = load_private_key(agent_key or REPOSITORY / DEFAULT_AGENT_KEY, "agent")
        token = request_agent_token(provider_url, agent)
    else:
        provider = load_private_key(provider_key or REPOSITORY / DEFAULT_PROVIDER_KEY, "provider")
        agent = load_private_key(agent_key, "agent") if agent_key is not None else Ed25519PrivateKey.generate()
        issuer = policy["issuer"]
        token = sign_agent_token(provider, issuer, provider_kid(config, provider, issuer), policy["subject"], agent)
    headers = signed_headers(authority, RESOURCE_PATH, agent, f'sig=jwt;jwt="{token}"', " ".join(scopes))
    return curl_command(url, headers, include_headers=include_headers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "provider_key", nargs="?", type=Path,
        help=f"Ed25519 provider private key in PEM or OpenSSH format (default: {DEFAULT_PROVIDER_KEY})",
    )
    parser.add_argument(
        "--provider-url", metavar="URL",
        help="agent provider base URL or /agent-token endpoint (uses the enrolled agent key)",
    )
    parser.add_argument(
        "--agent-key",
        type=Path,
        help=f"Ed25519 agent private key (default with --provider-url: {DEFAULT_AGENT_KEY}; otherwise disposable)",
    )
    parser.add_argument(
        "--print-curl",
        action="store_true",
        help="print the signed curl command before sending it",
    )
    parser.add_argument(
        "--scope", action="append", dest="scopes",
        help="SSH scope to register, repeatable (defaults to the sole configured scope)",
    )
    parser.add_argument(
        "--main-compose",
        nargs="?",
        const="",
        metavar="RESOURCE_URL",
        help="override the running Compose resource URL (default: server.issuer plus /agent/resource)",
    )
    args = parser.parse_args()
    try:
        command = configured_registration_command(
            args.provider_key, args.agent_key, args.provider_url, args.scopes, args.main_compose,
        )
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    if args.print_curl:
        print(shlex.join(command), flush=True)
    return subprocess.run(command).returncode


if __name__ == "__main__":
    raise SystemExit(main())
