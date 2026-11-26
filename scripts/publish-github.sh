#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
repo="${1:-wrldslatt999/pr5-7-secure-network}"
command -v gh >/dev/null || { echo 'GitHub CLI (gh) not installed' >&2;exit 1; }
gh auth status >/dev/null || { echo 'Run gh auth login first' >&2;exit 1; }
if [[ -d .git ]]; then
  echo 'Existing .git directory. Aborting to avoid damaging a repository.' >&2;exit 1
fi
printf 'Create PRIVATE GitHub repository %s and push sources? [y/N] ' "$repo"
read -r reply
[[ "$reply" =~ ^[yY]$ ]] || exit 0
# Ensure no local credentials/private keys end up in repo.
git init -b main
git add .
if git diff --cached --name-only | grep -E '(^|/)(\.env|ca\.key|server\.key|users\.sqlite3|client_session\.json)$'; then
  echo 'Sensitive file staged: aborting' >&2;exit 1
fi
git commit -m 'Implement secure two-node network lab with TLS MFA JWT and tests'
gh repo create "$repo" --private --source . --remote origin --push
printf 'Project uploaded: https://github.com/%s\n' "$repo"
