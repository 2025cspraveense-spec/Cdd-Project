#!/bin/sh
set -u

log_pipe="/tmp/mongodb-logs-$$"
umask 077
mkfifo "$log_pipe"

sed -E 's/"(user|username|password|pwd)"[[:space:]]*:[[:space:]]*"[^"]+"/"\1":"[REDACTED]"/g' < "$log_pipe" &
filter_pid=$!
/usr/local/bin/docker-entrypoint.sh "$@" > "$log_pipe" 2>&1 &
mongo_pid=$!

forward_term() {
    kill -TERM "$mongo_pid" 2>/dev/null || true
}

trap forward_term TERM INT
set +e
wait "$mongo_pid"
mongo_status=$?
while kill -0 "$mongo_pid" 2>/dev/null; do
    wait "$mongo_pid"
    mongo_status=$?
done
wait "$filter_pid"
filter_status=$?
rm -f "$log_pipe"

if [ "$mongo_status" -ne 0 ]; then
    exit "$mongo_status"
fi
exit "$filter_status"
