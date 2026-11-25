#!/bin/sh
set -eu

if [ "$#" -eq 2 ] && [ "$1" = v2 ]; then
    exec /usr/local/bin/kagome --ssh-command "$2"
fi

# Older registered keys supplied only the expiry and executable.
if [ "$#" -eq 2 ]; then
    set -- resource "$@"
fi

while [ "$#" -ge 3 ]; do
    if [ "${SSH_ORIGINAL_COMMAND:-}" = "$1" ]; then
        now=$(date +%s)
        if [ "$now" -ge "$2" ]; then
            printf '%s\n' 'SSH registration expired' >&2
            exit 126
        fi
        exec "$3" </dev/null
    fi
    shift 3
done

printf '%s\n' 'SSH command is not authorized' >&2
exit 126
