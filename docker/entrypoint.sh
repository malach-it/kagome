#!/bin/sh
set -eu

terminate() {
  if [ -n "${kagome_pid:-}" ]; then
    kill "$kagome_pid" 2>/dev/null || true
  fi

  if [ -n "${gateway_pid:-}" ]; then
    kill "$gateway_pid" 2>/dev/null || true
  fi
}

trap terminate INT TERM

kagome &
kagome_pid=$!

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
