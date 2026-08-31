#!/bin/sh
set -eu

validate_port() {
  case ${PORT:-} in
    ''|*[!0-9]*|??????*)
      echo "invalid PORT: expected an integer between 1 and 65535" >&2
      exit 1
      ;;
  esac

  if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "invalid PORT: expected an integer between 1 and 65535" >&2
    exit 1
  fi
}

render_boruta_configuration() {
  configuration_path=/etc/boruta/gateway.yml
  aliases_temporary_path="${configuration_path}.aliases.tmp"
  virtual_host_temporary_path="${configuration_path}.virtual-host.tmp"

  if ! grep -q '__BORUTA_GATEWAY_' "$configuration_path"; then
    return
  fi

  if [ -z "${BORUTA_GATEWAY_ALIASES:-}" ]; then
    echo "BORUTA_GATEWAY_ALIASES must not be empty" >&2
    exit 1
  fi

  if [ -z "${BORUTA_GATEWAY_VIRTUAL_HOST:-}" ]; then
    echo "BORUTA_GATEWAY_VIRTUAL_HOST must not be empty" >&2
    exit 1
  fi

  case $BORUTA_GATEWAY_ALIASES in
    \[*\]) ;;
    *)
      echo "invalid BORUTA_GATEWAY_ALIASES: expected a YAML array" >&2
      exit 1
      ;;
  esac

  aliases=$(printf '%s' "$BORUTA_GATEWAY_ALIASES" | sed 's/[\\&|]/\\&/g')
  virtual_host=$(
    printf '%s' "$BORUTA_GATEWAY_VIRTUAL_HOST" |
      sed 's/\\/\\\\/g; s/"/\\"/g; s/[&|]/\\&/g'
  )

  if ! sed "s|__BORUTA_GATEWAY_ALIASES__|$aliases|" \
    "$configuration_path" > "$aliases_temporary_path"; then
    rm -f "$aliases_temporary_path" "$virtual_host_temporary_path"
    echo "could not render BORUTA_GATEWAY_ALIASES" >&2
    exit 1
  fi

  if ! sed "s|__BORUTA_GATEWAY_VIRTUAL_HOST__|$virtual_host|" \
    "$aliases_temporary_path" > "$virtual_host_temporary_path"; then
    rm -f "$aliases_temporary_path" "$virtual_host_temporary_path"
    echo "could not render BORUTA_GATEWAY_VIRTUAL_HOST" >&2
    exit 1
  fi

  mv "$virtual_host_temporary_path" "$configuration_path"
  rm -f "$aliases_temporary_path"
}

terminate() {
  if [ -n "${kagome_pid:-}" ]; then
    kill "$kagome_pid" 2>/dev/null || true
  fi

  if [ -n "${gateway_pid:-}" ]; then
    kill "$gateway_pid" 2>/dev/null || true
  fi
}

trap terminate INT TERM

validate_port
render_boruta_configuration

kagome &
kagome_pid=$!

BORUTA_GATEWAY_SIDECAR_HTTPS_SERVER=true \
  BORUTA_GATEWAY_SIDECAR_HTTPS_PORT="$PORT" \
  BORUTA_GATEWAY_SIDECAR_HTTPS_VERIFY_CLIENT_CERTIFICATE=true \
  BORUTA_GATEWAY_CONFIGURATION_PATH=/etc/boruta/gateway.yml \
  /gateway/bin/boruta_gateway start &
gateway_pid=$!

while true; do
  if ! kill -0 "$kagome_pid" 2>/dev/null; then
    wait "$kagome_pid"
    exit $?
  fi

  if ! kill -0 "$gateway_pid" 2>/dev/null; then
    wait "$gateway_pid"
    exit $?
  fi

  sleep 1
done
