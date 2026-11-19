#!/bin/sh
set -u

log_pipe="/tmp/vault-logs-$$"
umask 077
mkfifo "$log_pipe"

sed -E 's/^(Root Token: ).*/\1[REDACTED]/' < "$log_pipe" &
filter_pid=$!
vault "$@" > "$log_pipe" 2>&1 &
vault_pid=$!

forward_term() {
    kill -TERM "$vault_pid" 2>/dev/null || true
}

trap forward_term TERM INT

attempt=0
ready=0
while [ "$attempt" -lt 60 ]; do
    if vault status -format=json >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "$vault_pid" 2>/dev/null; then
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done

if [ "$ready" -ne 1 ]; then
    printf '%s\n' "Vault did not become ready for bootstrap." > "$log_pipe"
    kill -TERM "$vault_pid" 2>/dev/null || true
    wait "$vault_pid"
    wait "$filter_pid"
    rm -f "$log_pipe"
    exit 1
fi

if [ "${VAULT_DATABASE_BOOTSTRAP:-false}" = "true" ]; then
    /bin/sh /usr/local/bin/vault-bootstrap.sh >> "$log_pipe" 2>&1
    bootstrap_status=$?
    if [ "$bootstrap_status" -ne 0 ]; then
        printf '%s\n' "Vault MongoDB bootstrap failed." > "$log_pipe"
        kill -TERM "$vault_pid" 2>/dev/null || true
        wait "$vault_pid"
        wait "$filter_pid"
        rm -f "$log_pipe"
        exit "$bootstrap_status"
    fi
fi

set +e
wait "$vault_pid"
vault_status=$?
while kill -0 "$vault_pid" 2>/dev/null; do
    wait "$vault_pid"
    vault_status=$?
done
wait "$filter_pid"
filter_status=$?
rm -f "$log_pipe"

if [ "$vault_status" -ne 0 ]; then
    exit "$vault_status"
fi
exit "$filter_status"
