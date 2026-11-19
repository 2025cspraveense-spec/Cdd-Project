#!/bin/sh
set -eu

: "${MONGO_APP_USERNAME:?MongoDB fallback username is required}"
: "${MONGO_APP_PASSWORD:?MongoDB fallback password is required}"

mongosh --quiet "$MONGO_INITDB_DATABASE" --eval \
    "db.createUser({user: \"$MONGO_APP_USERNAME\", pwd: \"$MONGO_APP_PASSWORD\", roles: [{role: \"readWrite\", db: \"$MONGO_INITDB_DATABASE\"}]})" \
    >/dev/null
