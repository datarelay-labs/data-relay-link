#!/usr/bin/env bash
# Lightweight documentation / version consistency assertions.
# Does not parse prose for style. Catches stale version and HTTP-enrollment slips.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pass() { echo "PASS $1"; }
fail() { echo "FAIL $1" >&2; exit 1; }

# shellcheck disable=SC1091
. "$ROOT/VERSION"
[[ "$PROJECT_VERSION" == "2.2.1" ]] || fail "VERSION project is $PROJECT_VERSION"
[[ "$FRP_VERSION" == "0.71.0" ]] || fail "VERSION FRP is $FRP_VERSION"
pass "VERSION_FILE"

grep -qF "Current project version: **${PROJECT_VERSION}**" README.md || fail "README project version"
grep -qF "**v${FRP_VERSION}**" README.md || fail "README FRP version"
if grep -nE 'Current project version: \*\*1\.(7|8|9)\.' README.md; then
  fail "README still shows a pre-2.0 current version"
fi
pass "README_VERSION"

[[ -f CHANGELOG.md ]] || fail "CHANGELOG.md missing"
[[ -f docs/SECURITY.md ]] || fail "docs/SECURITY.md missing"
[[ -f docs/DEPLOYMENT_MODES.md ]] || fail "docs/DEPLOYMENT_MODES.md missing"
[[ -f docs/CLI_REFERENCE.md ]] || fail "docs/CLI_REFERENCE.md missing"
[[ -f docs/RELEASE_CHECKLIST.md ]] || fail "docs/RELEASE_CHECKLIST.md missing"
[[ -f docs/RELEASE_VALIDATION.md ]] || fail "docs/RELEASE_VALIDATION.md missing"
pass "RELEASE_DOCS_PRESENT"

if grep -nE "FRP_ALLOCATOR_URL=['\"]http://" README.md docs/*.md examples/*.md 2>/dev/null; then
  fail "docs recommend an http:// allocator URL"
fi
pass "NO_HTTP_ENROLLMENT_DOCS"

if grep -nE 'FRP must (own|use|bind).*443|require[sd]? public TCP/443|hard-?coded.*443' README.md docs/*.md examples/*.md; then
  fail "docs treat TCP/443 as mandatory"
fi
pass "NO_FIXED_443_DOCS"

grep -q 'ssh -p <public-port>' README.md || fail "README missing public SSH example"
grep -q '\-\-one-line' README.md || fail "README missing zero-touch"
grep -q 'Client SSH user' README.md || fail "README interactive SSH user prompt"
grep -q '\-\-ssh-user' README.md || fail "README explicit --ssh-user"
grep -q 'no default username' README.md || fail "README missing no-default-username"
grep -qF 'does **not**:' README.md || fail "README missing zero-touch negatives"
pass "ZERO_TOUCH_DOCS"

for cmd in frpctl frp-create-client frp-client frp-client-info frp-clients \
  frp-client-set frp-release-service frp-release-client frp-revoke-client frp-update \
  frp-upstream frp-project-update frp-backup frp-restore frp-enrollments \
  frp-enroll-bulk frp-enrollment-revoke frp-server-status frp-server-set frp-set-client-installer-url; do
  [[ -e "$ROOT/tools/$cmd" ]] || fail "documented command missing: $cmd"
done
pass "DOCUMENTED_COMMANDS_EXIST"

grep -q 'ROCKY_9_SELINUX_ENFORCING=NOT_TESTED' docs/RELEASE_VALIDATION.md || fail "SELinux gate template"
if grep -nE 'fully supported on Rocky 9 SELinux Enforcing' README.md; then
  fail "README overclaims Rocky SELinux"
fi
# Checklist must not treat untested real gates as mandatory checkbox requirements.
if grep -nE '^- \[ \] Rocky Linux 9 (real VM|SELinux)|^- \[ \] AlmaLinux 9 (real VM|SELinux)|^- \[ \] Amazon Linux|^- \[ \] Native ARM64|^- \[ \] Real OpenSSL 1\.0\.2' docs/RELEASE_CHECKLIST.md; then
  fail "checklist still lists untested real gates as mandatory checkboxes"
fi
grep -q 'authoritative' docs/RELEASE_CHECKLIST.md || fail "checklist missing authoritative pointer"
grep -q 'Authoritative classification' docs/RELEASE_CHECKLIST.md || fail "checklist missing classification pointer"
grep -q 'authoritative' docs/RELEASE_VALIDATION.md || fail "validation missing authoritative wording"
pass "SUPPORT_CLAIM_ALIGNMENT"

if grep -nE 'hashed/wrapped server-side' docs/SECURITY.md; then
  fail "SECURITY.md still claims enrollment secret is hashed/wrapped"
fi
grep -q 'not hashed or wrapped at rest' docs/SECURITY.md || fail "SECURITY.md missing enrollment secret storage accuracy"
grep -q 'BOOTSTRAP_TICKET_USED' docs/SECURITY.md || fail "SECURITY.md missing post-success ticket reuse class"
pass "SECURITY_DOC_SECRET_ACCURACY"

if grep -nE "curl[[:space:]]+[^|]*--cacert[[:space:]]+/tmp/" README.md docs/*.md examples/*.md 2>/dev/null; then
  fail "docs use --cacert with a /tmp CA path that may not exist"
fi
if grep -nE 'curl[[:space:]]+[^|]*--cacert[[:space:]]+[^ ]+[[:space:]]+https://[^ ]+/ca\.crt' README.md docs/*.md examples/*.md 2>/dev/null; then
  fail "docs imply downloading /ca.crt with --cacert (invalid first-trust)"
fi
pass "MANUAL_CA_BOOTSTRAP_DOCS"

# Production verification must not recommend curl -k. A commented transport-only
# diagnostic in DEPLOYMENT_MODES.md is the only allowed occurrence.
if grep -nE '^[[:space:]]*curl[[:space:]].*((^|[[:space:]])-k([[:space:]]|$)|--insecure)' README.md docs/*.md examples/*.md 2>/dev/null; then
  fail "docs recommend curl -k/--insecure as an active command"
fi
if grep -nE 'curl -k' README.md docs/SECURITY.md docs/RELEASE_CHECKLIST.md examples/*.md 2>/dev/null \
  | grep -v 'not used' | grep -v 'Do not' | grep -v 'do not'; then
  fail "docs present curl -k as a verification flow"
fi
pass "NO_CURL_K_PRODUCTION_FLOW"

if grep -nE 'allocator public URL must be HTTPS|plain HTTP is not supported' "$ROOT/install-server.sh" >/dev/null; then
  :
else
  fail "installer missing HTTP allocator rejection"
fi
if grep -nE "FRP_ALLOCATOR_URL=['\"]http://" README.md docs/*.md; then
  fail "docs still show http allocator"
fi
pass "NO_HTTP_ALLOCATOR"

if grep -nE 'proxy_ssl_verify[[:space:]]+off' "$ROOT/lib/frp_frontend.py" "$ROOT/install-server.sh"; then
  fail "production frontend disables proxy_ssl_verify"
fi
if grep -nE 'curl[[:space:]].*((^|[[:space:]])-k([[:space:]]|$)|--insecure)' "$ROOT/lib/frp_doctor.py" "$ROOT/install-server.sh"; then
  fail "installer/doctor use curl -k"
fi
pass "NO_TLS_VERIFY_DISABLE"
pass "NO_CURL_K_PRODUCTION_FLOW"

if grep -nE 'release candidate' README.md CHANGELOG.md docs/SECURITY.md docs/DEPLOYMENT_MODES.md; then
  fail "docs still describe the current release as a release candidate"
fi
if grep -nE 'v2\.1\.1 is not tagged|not a tagged stable release until|not created until real-environment' README.md CHANGELOG.md docs/*.md; then
  fail "docs still say v2.1.1 is untagged"
fi
grep -qF 'current stable release' README.md || fail "README missing stable wording"
grep -qE '^## 2\.1\.1 — ' CHANGELOG.md || fail "CHANGELOG missing 2.1.1 heading"
grep -qE '^## 2\.1\.0 — ' CHANGELOG.md || fail "CHANGELOG missing historical 2.1.0 heading"
pass "VERSION_STABLE_WORDING"

grep -qF "v${PROJECT_VERSION}/dist/bootstrap-server.sh" README.md || fail "README missing immutable server bootstrap URL"
if grep -nE 'raw.githubusercontent.com/(datarelay-labs|xdr-labs)/frp-auto-deploy/main/dist/bootstrap-(server|client)\.sh' \
  README.md docs/SCHEMA_V2_DEPLOYMENT.md docs/DEPLOYMENT_MODES.md GITHUB_SETUP.md; then
  fail "stable docs still point bootstrap installs at mutable main"
fi
if grep -nE 'datarelay-labs/frp-auto-deploy' \
  README.md docs/SCHEMA_V2_DEPLOYMENT.md docs/DEPLOYMENT_MODES.md docs/FRP_UPGRADE.md docs/PRODUCT_MASTER.md GITHUB_SETUP.md; then
  fail "stable docs still reference old repository owner datarelay-labs"
fi
grep -qF 'xdr-labs/frp-auto-deploy' README.md GITHUB_SETUP.md docs/PRODUCT_MASTER.md ||
  fail "docs missing canonical xdr-labs repository"
grep -q 'FRP_RELEASE_CHANNEL=dev' README.md || fail "README missing opt-in dev channel note"
grep -q 'one-time verified bridge' README.md || fail "README missing legacy client bridge"
grep -q 'one-time verified bridge' docs/FRP_UPGRADE.md || fail "upgrade doc missing legacy bridge"
grep -q 'cannot retroactively verify' docs/FRP_UPGRADE.md || fail "upgrade doc missing old-updater limit"
grep -q 'do not pipe' docs/FRP_UPGRADE.md || grep -q 'Do not pipe' docs/FRP_UPGRADE.md ||
  fail "upgrade doc must not recommend piping main"
pass "IMMUTABLE_RELEASE_URLS_IN_DOCS"

grep -q 'REAL_ENTERPRISE_RESTRICTED_NETWORK_E2E=PASS' docs/RELEASE_VALIDATION.md || fail "missing enterprise-network evidence"
grep -q 'REAL_SSH_SERVICE_E2E=PASS' docs/RELEASE_VALIDATION.md || fail "missing SSH E2E evidence"
grep -q 'REAL_END_TO_END_REBOOT_RECOVERY=PASS' docs/RELEASE_VALIDATION.md || fail "missing reboot-recovery evidence"
grep -q 'FIREWALL_DNAT_PRIVATE_FRP_SERVER=NOT_TESTED' docs/RELEASE_VALIDATION.md || fail "DNAT limitation missing"
grep -q 'REAL_ARM_SYSTEMD=NOT_TESTED' docs/RELEASE_VALIDATION.md || fail "ARM64 limitation missing"
grep -q 'REAL_OPENSSL_1_0_2_TLS_ENROLLMENT=NOT_TESTED' docs/RELEASE_VALIDATION.md || fail "OpenSSL 1.0.2 limitation missing"
pass "REAL_ACCEPTANCE_RECORDED"

chmod +x "$ROOT/scripts/validate-release-tag.sh"
TMPERR="$(mktemp)"
if "$ROOT/scripts/validate-release-tag.sh" v2.1.4 >/dev/null 2>"$TMPERR"; then
  rm -f "$TMPERR"
  fail "v2.1.4 must not validate against PROJECT_VERSION=${PROJECT_VERSION}"
fi
grep -q "PROJECT_VERSION=${PROJECT_VERSION}" "$TMPERR" || fail "tag mismatch diagnostic"
rm -f "$TMPERR"
"$ROOT/scripts/validate-release-tag.sh" "v${PROJECT_VERSION}" >/dev/null || fail "current VERSION tag should validate"
grep -q 'Do \*\*not\*\* tag a tree whose `PROJECT_VERSION` does not match' docs/RELEASE_CHECKLIST.md ||
  fail "checklist missing release version gate procedure"
pass "P1_RELEASE_VERSION_GATE"

echo "RELEASE_DOCS_TEST=PASS"
