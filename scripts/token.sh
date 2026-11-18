#!/usr/bin/env bash
# Prints an access token for one of identity-service's users (alice, bob, carol, admin; password "password"), using the
# authorization_code flow without a browser, as in identity-service's README. Usage: scripts/token.sh admin
set -euo pipefail

USER_NAME=${1:?usage: scripts/token.sh <alice|bob|carol|admin>}
AS=${AUTHTRACER_ISSUER:-http://localhost:9000}
REDIRECT=http://127.0.0.1:8099/callback
SCOPES='openid%20profile%20employees.read%20employees.write'
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

AUTHZ="$AS/oauth2/authorize?response_type=code&client_id=authtracer-driver&scope=$SCOPES&redirect_uri=$REDIRECT&state=xyz"
curl -sf -c "$JAR" -b "$JAR" -H 'Accept: text/html' -o /dev/null "$AUTHZ"
CSRF=$(curl -sf -c "$JAR" -b "$JAR" "$AS/login" | sed -n 's/.*name="_csrf" type="hidden" value="\([^"]*\)".*/\1/p')
NEXT=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' --data-urlencode "username=$USER_NAME" \
  --data-urlencode password=password --data-urlencode "_csrf=$CSRF" "$AS/login")
CALLBACK=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$NEXT")
CODE=$(printf '%s' "$CALLBACK" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
if [ -z "$CODE" ]; then
  echo "No authorization code for $USER_NAME (login redirected to: ${NEXT:-nothing})" >&2
  exit 1
fi
curl -sf -u authtracer-driver:driver-secret -d grant_type=authorization_code --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT" "$AS/oauth2/token" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
