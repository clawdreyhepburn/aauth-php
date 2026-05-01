#!/usr/bin/env bash
#
# Deploy wisdom-deploy/ to wisdom.clawdrey.com.
#
# Usage:
#   ./scripts/deploy-wisdom.sh         # rebuild bundle, sync, fix perms, smoke test
#   ./scripts/deploy-wisdom.sh --skip-build
#
# Requires:
#   - sshpass (brew install hudochenkov/sshpass/sshpass)
#   - DreamHost password file at /tmp/dhwisdom.pw (mode 600)
#   - The wisdom.clawdrey.com SFTP account already provisioned

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CRED_FILE="${HOME}/.openclaw/credentials/dreamhost-wisdom.json"
PW_FILE="/tmp/dhwisdom.pw"
HOST="pdx1-shared-a2-13.dreamhost.com"
USER="dh_vmtb7d"
REMOTE="wisdom.clawdrey.com"

if [[ ! -f "$PW_FILE" ]]; then
    if [[ -f "$CRED_FILE" ]]; then
        # shellcheck disable=SC2002
        cat "$CRED_FILE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["password"], end="")' > "$PW_FILE"
        chmod 600 "$PW_FILE"
    else
        echo "ERROR: no $PW_FILE and no $CRED_FILE to derive it from" >&2
        exit 1
    fi
fi

if ! command -v sshpass >/dev/null 2>&1; then
    echo "ERROR: sshpass not installed (brew install hudochenkov/sshpass/sshpass)" >&2
    exit 1
fi

if [[ "${1:-}" != "--skip-build" ]]; then
    echo "==> Rebuilding bundle"
    php scripts/build-bundle.php
    cp dist/aauth-bundle.php wisdom-deploy/aauth-bundle.php
    echo "==> Running test suite"
    php tests/run-all.php
fi

SSH_CMD="sshpass -f $PW_FILE ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password -o StrictHostKeyChecking=accept-new"

echo "==> Syncing wisdom-deploy/ to $USER@$HOST:$REMOTE/"
# IMPORTANT: --no-perms / --chmod is required because local files may be
# mode 600 (credentials hygiene) but Apache needs 644/755 to serve them.
# We let rsync transfer content/timestamps but rewrite permissions on the
# wire, so the server always ends up with web-readable files.
rsync \
    -e "$SSH_CMD" \
    --recursive --times --links --delete \
    --no-perms --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
    wisdom-deploy/ "$USER@$HOST:$REMOTE/"

echo "==> Belt-and-suspenders chmod on the server"
$SSH_CMD "$USER@$HOST" \
    "cd $REMOTE && find . -type d -exec chmod 755 {} \\; && find . -type f -exec chmod 644 {} \\;"

echo "==> Smoke testing"
expect_codes=(
    "https://wisdom.clawdrey.com/                              200"
    "https://wisdom.clawdrey.com/.well-known/aauth-resource    200"
    "https://wisdom.clawdrey.com/wisdom/foundations            401"
    "https://wisdom.clawdrey.com/wisdom/situational            401"
)

fail=0
for line in "${expect_codes[@]}"; do
    url="$(awk '{print $1}' <<<"$line")"
    want="$(awk '{print $2}' <<<"$line")"
    got="$(curl -s -o /dev/null -w '%{http_code}' "$url")"
    if [[ "$got" == "$want" ]]; then
        printf "  ✓ %-60s %s\n" "$url" "$got"
    else
        printf "  ✗ %-60s want %s got %s\n" "$url" "$want" "$got"
        fail=1
    fi
done

if [[ $fail -eq 0 ]]; then
    echo "==> Deploy complete. ✓"
else
    echo "==> Deploy completed with smoke-test failures. ✗" >&2
    exit 1
fi
