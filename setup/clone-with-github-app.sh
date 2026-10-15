#!/bin/bash
# Run as the separate agent OS user. Uses only a GitHub App private key: makes a 9-minute app
# token, swaps it for a 1-hour installation token, then clones (or updates) the agent repo.
# Secrets never appear in process arguments, URLs or .git/config: curl reads its header from a
# 0600 file (-K), git asks GIT_ASKPASS, and the folder holding both is removed on any exit.
# printf is a shell builtin, so writing them starts no process.
#
# Settings (environment, or edit here):
#   AGENT_APP_ID    your GitHub App's numeric id
#   AGENT_APP_KEY   the App's private key, mode 600, owned by the agent user
#   AGENT_REPO_URL  https://github.com/YOUR-ORG/YOUR-AGENT-REPO.git
#   AGENT_CHECKOUT  folder name under $HOME (default: supervised-agent)
set -euo pipefail
umask 077
cd "$HOME"
APP_ID=${AGENT_APP_ID:?set AGENT_APP_ID}
KEY=${AGENT_APP_KEY:-$HOME/.config/supervised-agent/github-app.pem}
REPO=${AGENT_REPO_URL:?set AGENT_REPO_URL}
DIR=${AGENT_CHECKOUT:-supervised-agent}
[ "$(stat -f %Lp "$KEY")" = 600 ] || { echo "key must be mode 600: $KEY"; exit 1; }
SECRETS=$(mktemp -d)
trap 'rm -rf "$SECRETS"' EXIT
b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
json() { /usr/bin/python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
api() {  # api <token file> <curl args...>; the token goes in a curl config file, never in argv
  printf 'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\n' "$(cat "$1")" > "$SECRETS/curl"
  curl -fsS -K "$SECRETS/curl" "${@:2}"
}
now=$(date +%s)
header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64)
payload=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' $((now-60)) $((now+540)) "$APP_ID" | b64)
sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$KEY" -binary | b64)
printf '%s.%s.%s' "$header" "$payload" "$sig" > "$SECRETS/jwt"
inst=$(api "$SECRETS/jwt" https://api.github.com/app/installations | json 'd[0]["id"]')
api "$SECRETS/jwt" -X POST "https://api.github.com/app/installations/$inst/access_tokens" | json 'd["token"]' > "$SECRETS/token"
rm -f "$SECRETS/jwt"
echo "Repos the app can reach:"
api "$SECRETS/token" https://api.github.com/installation/repositories | json '[r["full_name"] for r in d["repositories"]]'
printf '#!/bin/sh\ncase "$1" in Username*) echo x-access-token ;; *) cat "%s" ;; esac\n' "$SECRETS/token" > "$SECRETS/askpass"
chmod 700 "$SECRETS/askpass"
export GIT_ASKPASS="$SECRETS/askpass" GIT_TERMINAL_PROMPT=0
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" -c credential.helper= pull -q --ff-only "$REPO" main
else
  git -c credential.helper= clone -q "$REPO" "$DIR"
fi
git -C "$DIR" remote get-url origin
git -C "$DIR" log --oneline -1
