#!/bin/sh
set -eu

umask 077

work_path=/tmp/forgejo-ci
config_path="$work_path/custom/conf/app.ini"

: "${FORGEJO_BOOTSTRAP_USERNAME:?FORGEJO_BOOTSTRAP_USERNAME is required}"
: "${FORGEJO_BOOTSTRAP_PASSWORD:?FORGEJO_BOOTSTRAP_PASSWORD is required}"
: "${FORGEJO_BOOTSTRAP_EMAIL:?FORGEJO_BOOTSTRAP_EMAIL is required}"

mkdir -p "$work_path/custom/conf" "$work_path/data" "$work_path/log" \
  "$work_path/repositories" "$work_path/tmp/gitea"
export TMPDIR="$work_path/tmp"

cat >"$config_path" <<EOF
APP_NAME = forge-mcp CI
RUN_MODE = prod
WORK_PATH = $work_path

[repository]
ROOT = $work_path/repositories

[server]
PROTOCOL = http
HTTP_ADDR = 0.0.0.0
HTTP_PORT = 3000
ROOT_URL = http://forgejo:3000/
DISABLE_SSH = true
APP_DATA_PATH = $work_path/data

[database]
DB_TYPE = sqlite3
PATH = $work_path/data/forgejo.db

[security]
INSTALL_LOCK = true

[service]
DISABLE_REGISTRATION = true

[log]
MODE = console
LEVEL = Info
ROOT_PATH = $work_path/log
EOF

forgejo --work-path "$work_path" --config "$config_path" migrate
forgejo --work-path "$work_path" --config "$config_path" admin user create \
  --username "$FORGEJO_BOOTSTRAP_USERNAME" \
  --password "$FORGEJO_BOOTSTRAP_PASSWORD" \
  --email "$FORGEJO_BOOTSTRAP_EMAIL" \
  --must-change-password=false

exec forgejo --work-path "$work_path" --config "$config_path" web
