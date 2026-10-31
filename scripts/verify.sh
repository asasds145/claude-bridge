#!/usr/bin/env bash
# Read-only HTTP smoke checks against a deployed bridge. Never prints the Chief key.
# Does not load .env. Export BRIDGE_URL and CHIEF_HEADER_FILE yourself.
# Usage: BRIDGE_URL=https://... CHIEF_HEADER_FILE=./chief.hdr bash scripts/verify.sh
set -u
H=${BRIDGE_URL:?set BRIDGE_URL, e.g. https://chief-bridge.<sub>.workers.dev}; H=${H%/}
HDR=${CHIEF_HEADER_FILE:-${1:-./chief.hdr}}
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

[ "$(code "$H/health")" = 200 ] && ok "/health 200" || bad "/health"
[ "$(code "$H/chief/health")" = 401 ] && ok "/chief/health no key 401" || bad "/chief/health no key"
[ "$(code "$H/chief/inbox")" = 401 ] && ok "/chief/inbox no key 401" || bad "/chief/inbox no key"
if [ -r "$HDR" ]; then
  [ "$(code -H @"$HDR" "$H/chief/health")" = 200 ] && ok "/chief/health with key 200" || bad "/chief/health with key"
else bad "key file $HDR not readable"; fi

hdrs=$(curl -s -o /dev/null -D - -X POST -H 'content-type: application/json' -d '{}' "$H/mcp")
echo "$hdrs" | head -1 | grep -q ' 401' && ok "/mcp POST 401" || bad "/mcp POST status"
echo "$hdrs" | grep -i '^www-authenticate:' | grep -q "resource_metadata=\"$H/.well-known/oauth-protected-resource/mcp\"" && ok "www-authenticate resource_metadata" || bad "www-authenticate resource_metadata"

prm=$(curl -s "$H/.well-known/oauth-protected-resource/mcp")
echo "$prm" | grep -q "\"resource\":\"$H/mcp\"" && ok "PRM resource" || bad "PRM resource: $prm"
echo "$prm" | grep -q '"resource_name":"chief-bridge"' && ok "PRM resource_name" || bad "PRM resource_name"

as=$(curl -s "$H/.well-known/oauth-authorization-server")
for k in "\"issuer\":\"$H\"" '"S256"' '"client_id_metadata_document_supported":true' '"none"' '"offline_access"'; do
  echo "$as" | grep -qF "$k" && ok "AS metadata $k" || bad "AS metadata $k"
done

# Display name: an invalid client on /authorize renders an error page titled chief-bridge
# (503 before GITHUB_CLIENT_SECRET is set, 400 after; same title either way)
a=$(curl -s -w '\n%{http_code}' "$H/authorize?response_type=code&client_id=x")
st=$(echo "$a" | tail -1)
echo "$a" | grep -q '<title>chief-bridge</title>' && ok "auth page title chief-bridge (status $st)" || bad "auth page title (status $st)"
[ "$st" = 400 ] && ok "GITHUB_CLIENT_SECRET set (400 not 503)" || bad "/authorize status $st (503 = GITHUB_CLIENT_SECRET not set yet)"

echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
