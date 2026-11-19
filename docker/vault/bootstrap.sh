#!/bin/sh
set -eu

: "${MONGO_INITDB_ROOT_USERNAME:?MongoDB root username is required}"
: "${MONGO_INITDB_ROOT_PASSWORD:?MongoDB root password is required}"

if ! vault secrets list -format=json | grep -q '"database/"'; then
    vault secrets enable -path=database database >/dev/null
fi

vault write database/config/mongodb \
    plugin_name=mongodb-database-plugin \
    allowed_roles=slg-backend-role \
    connection_url='mongodb://{{username}}:{{password}}@mongodb:27017/admin?authSource=admin' \
    username="$MONGO_INITDB_ROOT_USERNAME" \
    password="$MONGO_INITDB_ROOT_PASSWORD" >/dev/null

vault write database/roles/slg-backend-role \
    db_name=mongodb \
    creation_statements='{"db":"secret_leak_guard_v2","roles":[{"role":"readWrite","db":"secret_leak_guard_v2"}]}' \
    revocation_statements='{"db":"secret_leak_guard_v2","dropUser":"{{name}}"}' \
    default_ttl=1h \
    max_ttl=24h >/dev/null

if vault kv get -format=json secret/secret-leak-guard >/dev/null 2>&1; then
    vault kv patch secret/secret-leak-guard \
        MONGO_APP_USERNAME="$MONGO_APP_USERNAME" \
        MONGO_APP_PASSWORD="$MONGO_APP_PASSWORD" >/dev/null
else
    vault kv put secret/secret-leak-guard \
        MONGO_APP_USERNAME="$MONGO_APP_USERNAME" \
        MONGO_APP_PASSWORD="$MONGO_APP_PASSWORD" >/dev/null
fi

printf '%s\n' "Vault MongoDB database engine and role are configured."
