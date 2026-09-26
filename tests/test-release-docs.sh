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
[[ -n "${PROJECT_VERSION:-}" ]] || fail "VERSION missing PROJECT_VERSION"
[[ -n "${FRP_VERSION:-}" ]] || fail "VERSION missing FRP_VERSION"
pass "VERSION_FILE"

# VERSION is the single source of truth. Cross-document agreement, and the
# published-tag immutability policy, are asserted there rather than by
# repeating version literals in this file.
"$ROOT/scripts/check-version-consistency.sh" || fail "version consistency"
pass "VERSION_CONSISTENCY"

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
grep -qF 'set enrollment zero-touch' README.md || fail "README missing current zero-touch vocabulary"
# Stale v2.3 client/one-line grammar must not reappear as the public Zero-Touch contract.
if grep -nE 'set client --one-line|create zero-touch|create enrollment[[:space:]]+\\|--one-line|--ssh-user|Client SSH user' README.md README.ko.md; then
  fail "README still advertises superseded Zero-Touch / client grammar"
fi
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

if grep -nE 'not hashed or wrapped at rest' docs/SECURITY.md; then
  fail "SECURITY.md still claims enrollment secret is stored unhashed"
fi
grep -q 'verifier/hash' docs/SECURITY.md || fail "SECURITY.md missing enrollment secret storage accuracy"
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

# Development-channel trees must state truthful development/target status.
# Do not invent a current stable-line badge from a historical tag alone, and
# do not require candidate/RC wording unless RELEASE_CHANNEL is actually preview.
if grep -qiE "development target|RELEASE_CHANNEL=development|channel-development|v${PROJECT_VERSION} development" README.md; then
  :
else
  fail "README missing truthful development-channel / development-target wording"
fi
if grep -nE 'stable%20line|badge/stable|Stable line v|published stable line|current stable line|candidate-v|Candidate v|badge/candidate|Prepared release —' README.md README.ko.md; then
  fail "README invents stable-line or candidate/RC designation inconsistent with development channel"
fi
# Pre-tag safety: if the immutable tag URL is advertised as the install command,
# README must also warn that the tag may not exist yet (avoid silent 404 hazard).
if grep -qF "v${PROJECT_VERSION}/dist/bootstrap-server.sh" README.md; then
  if ! grep -qiE "until.*(tag|v${PROJECT_VERSION}).*exist|tag pending|after.*tag.*(publish|creat)|would 404" README.md; then
    fail "README advertises v${PROJECT_VERSION} install URL without pre-tag sequencing warning"
  fi
fi
if grep -nE 'v2\.1\.1 is not tagged|not a tagged stable release until|not created until real-environment' README.md CHANGELOG.md docs/*.md; then
  fail "docs still say v2.1.1 is untagged"
fi
if grep -nE 'stable identity remains \*\*v2\.2\.1|stable release identity remains \*\*v2\.2\.1' README.md; then
  fail "README still claims v2.2.1 as current stable identity"
fi
grep -qE '^## 2\.1\.1 — ' CHANGELOG.md || fail "CHANGELOG missing 2.1.1 heading"
grep -qE '^## 2\.1\.0 — ' CHANGELOG.md || fail "CHANGELOG missing historical 2.1.0 heading"
pass "VERSION_STABLE_WORDING"

grep -qF "v${PROJECT_VERSION}/dist/bootstrap-server.sh" README.md || fail "README missing intended immutable server bootstrap URL"
if grep -nE 'raw.githubusercontent.com/(datarelay-labs|xdr-labs)/frp-auto-deploy/main/dist/bootstrap-(server|client)\.sh' \
  README.md docs/SCHEMA_V2_DEPLOYMENT.md docs/DEPLOYMENT_MODES.md GITHUB_SETUP.md; then
  fail "stable docs still point bootstrap installs at mutable main"
fi
if grep -nE 'datarelay-labs/frp-auto-deploy' \
  README.md docs/SCHEMA_V2_DEPLOYMENT.md docs/DEPLOYMENT_MODES.md docs/FRP_UPGRADE.md docs/PRODUCT_MASTER.md GITHUB_SETUP.md; then
  fail "stable docs still reference old repository owner datarelay-labs"
fi
grep -qF 'datarelay-labs/datarelay-link' README.md GITHUB_SETUP.md ||
  fail "docs missing canonical datarelay-labs/datarelay-link repository"
if grep -nE 'github\.com/datarelay-labs/data-relay-link|raw\.githubusercontent\.com/datarelay-labs/data-relay-link' \
  README.md GITHUB_SETUP.md docs/DEPLOYMENT_MODES.md docs/FRP_UPGRADE.md; then
  fail "stable docs still advertise pre-rename datarelay-labs/data-relay-link as canonical"
fi
grep -q 'FRP_RELEASE_CHANNEL=dev' README.md || fail "README missing opt-in dev channel note"
grep -q 'one-time verified bridge' README.md || fail "README missing legacy client bridge"
grep -q 'one-time verified bridge' docs/FRP_UPGRADE.md || fail "upgrade doc missing legacy bridge"
grep -q 'cannot retroactively verify' docs/FRP_UPGRADE.md || fail "upgrade doc missing old-updater limit"
grep -q 'do not pipe' docs/FRP_UPGRADE.md || grep -q 'Do not pipe' docs/FRP_UPGRADE.md ||
  fail "upgrade doc must not recommend piping main"
pass "IMMUTABLE_RELEASE_URLS_IN_DOCS"

# Current operator/setup/release surfaces must not advertise nonexistent v2.3.1
# as a project version, installer ref, or Homebrew tarball. Saying the tag was
# not manufactured is allowed.
CURRENT_RELEASE_SURFACES=(
  GITHUB_SETUP.md
  docs/DEPLOYMENT_MODES.md
  docs/FRP_UPGRADE.md
  docs/VERSION_POLICY.md
  docs/RELEASE_CHECKLIST.md
  windows/README.md
  packaging/homebrew/Formula/data-relay-link.rb
)
if grep -nE 'v2\.3\.1/|tags/v2\.3\.1|PROJECT_VERSION=2\.3\.1|version "2\.3\.1"|Current release.*2\.3\.1|\*\*2\.3\.1\*\*' \
  "${CURRENT_RELEASE_SURFACES[@]}"; then
  fail "current surface still presents v2.3.1 as a release"
fi
if grep -nE 'raw\.githubusercontent\.com/.*/v2\.4\.0/|archive/refs/tags/v2\.4\.0|url ".*v2\.4\.0' \
  GITHUB_SETUP.md packaging/homebrew/Formula/data-relay-link.rb; then
  fail "setup/packaging advertises a future v2.4.0 tag URL"
fi
pass "NO_FABRICATED_V231_RELEASE_SURFACE"

grep -q 'Documented stable baseline             v2.3.0' docs/VERSION_POLICY.md \
  || fail "VERSION_POLICY prior stable is not v2.3.0"
grep -q 'Not manufactured                       v2.3.1' docs/VERSION_POLICY.md \
  || fail "VERSION_POLICY must record that v2.3.1 was not manufactured"
grep -q 'PRIOR_STABLE_VERSION=2.3.0' tests/run-v230-to-v240-upgrade-e2e.sh \
  || fail "upgrade harness prior stable is not v2.3.0"
if grep -nE 'PRIOR_STABLE_VERSION=2\.2\.1|run-v221-to-v240-upgrade-e2e' \
  tests/run-v230-to-v240-upgrade-e2e.sh tests/run-prod-qual-extended.sh docs/FRP_UPGRADE.md; then
  fail "prior-stable upgrade lane still targets v2.2.1"
fi
if grep -q 'Candidate identity is `2.4.0-rc.N` / `preview` before stable' docs/RELEASE_CHECKLIST.md; then
  fail "RELEASE_CHECKLIST still makes preview/RC mandatory"
fi
grep -q 'Preview/RC is not mandatory' docs/RELEASE_CHECKLIST.md \
  || fail "RELEASE_CHECKLIST missing optional preview/RC wording"
grep -q 'no tracked commit is created after PASS2' docs/RELEASE_CHECKLIST.md \
  || fail "RELEASE_CHECKLIST missing no-commit-after-PASS2 rule"
for obsolete in \
  docs/MORNING_E2E_CHECKLIST.md \
  docs/MORNING_REAL_E2E_FINAL_CHECKLIST.md \
  docs/V2_4_0_CURSOR_AUTOMATED_E2E_PLAN.md \
  docs/V2_4_0_RICK_CURSOR_EVIDENCE_MATRIX.md; do
  if [[ -e "$obsolete" ]]; then
    fail "obsolete checklist still present: $obsolete"
  fi
done
pass "PRIOR_STABLE_V230_AND_DOC_HYGIENE"

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

# Public documentation must describe visible canonical commands only.
# Hidden compatibility aliases do not satisfy this gate.
python3 "$ROOT/tests/test-release-recovery-dual-role-audit-docs-closure.py" \
  ReleaseRecoveryDualRoleAuditDocsClosure.test_public_doc_command_parity \
  ReleaseRecoveryDualRoleAuditDocsClosure.test_hidden_aliases_not_advertised_in_normal_help \
  || fail "PUBLIC_DOC_COMMAND_PARITY"
pass "PUBLIC_DOC_COMMAND_PARITY"

echo "RELEASE_DOCS_TEST=PASS"
