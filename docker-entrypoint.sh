#!/bin/sh
set -eu

if [ -n "${KAGOME_SSH_PUBLIC_KEY:-}" ] || [ "${KAGOME_AGENT_SSH_ENABLED:-}" = 1 ]; then
    (
        umask 077
        ssh_dir=/home/kagome/.ssh
        runtime_dir=/run/kagome-ssh
        host_key="$ssh_dir/host_ed25519_key"

        if [ ! -f "$host_key" ]; then
            dropbearkey -t ed25519 -f "$host_key" > /dev/null
        fi

        dropbear -E -p 2222 -r "$host_key" -D "$runtime_dir" -P "$runtime_dir/dropbear.pid" -w -s -j -k
        printf '%s\n' "${KAGOME_SSH_PUBLIC_KEY:-}" > "$runtime_dir/authorized_keys"
    )
fi

exec "$@"
