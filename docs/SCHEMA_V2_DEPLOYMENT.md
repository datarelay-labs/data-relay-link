# Schema v2 deployment runbook

This release uses registry schema version 2 (generic multi-service clients). Schema v1 SSH/HTTPS registries are **not** migrated automatically.

The addresses `203.0.113.10` and `192.0.2.50` in this document are RFC documentation examples. Replace them with values from your environment.

Do not rotate `/etc/frp/server_token` or rewrite `/etc/frp/frps.toml` as part of a registry schema change. Token preservation and FRP control settings are independent of the allocator registry.

This procedure is for an existing server that still has a v1 registry, or for a fresh install. It does not change a remote production host by itself.

---

## 1. Check current status

On the FRP server:

```bash
sudo drlink status
sudo drlink status
sudo drlink status --check
```

Read:

```text
Registry schema
Registry state
Allocator URL
Public host
frps
allocator
```

`--check` exits `0` only when schema v2 is present and public host plus allocator URL are configured.

If the output shows schema `1` / `incompatible`, continue with the backup and reset steps below. If it already shows schema `2` / `ready`, skip the reset and go to verification.

---

## 2. Back up token, config, and registry

Create a timestamped backup **before** any registry change. Do not print registry contents to the terminal.

```bash
sudo install -d -m 700 /var/lib/drlink/backups
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -m 600 /etc/frp/server_token \
  "/var/lib/drlink/backups/server_token.${STAMP}"
sudo install -m 600 /etc/drlink/config.json \
  "/var/lib/drlink/backups/config.json.${STAMP}"
if [[ -f /var/lib/drlink/registry.json ]]; then
  sudo install -m 600 /var/lib/drlink/registry.json \
    "/var/lib/drlink/backups/registry.json.pre-schema-v2-${STAMP}"
fi
sudo ls -l /var/lib/drlink/backups
```

Keep those backups. Never delete them as part of this procedure.

Confirm the token backup exists, then leave `/etc/frp/server_token` in place.

---

## 3. Confirm the registry is schema v1 (or missing)

```bash
sudo python3 - <<'PY'
from pathlib import Path
p = Path('/var/lib/drlink/registry.json')
print('exists', p.exists())
if p.exists():
    import json
    data = json.loads(p.read_text(encoding='utf-8'))
    print('schema_version', data.get('schema_version', '(missing, treat as v1)'))
PY
```

Do not dump the full registry.

A missing `schema_version` or value `1` is unsupported by this release. A future version such as `3` is also unsupported; do not rewrite it to v2 in place.

---

## 4. Stop or uninstall old clients if required

Existing v1 client allocations are not imported. Plan to re-enroll each Linux client after the registry is replaced.

On each old client, stop or uninstall `frpc` so previously published ports are no longer in use:

```bash
sudo systemctl stop drlink-client
```

or use the client uninstall helper. Server-side port reservations in the v1 registry will be discarded in the next step; live listeners are still scanned and reserved during server install.

---

## 5. Replace the registry with schema v2

Stop the allocator first so it cannot rewrite the old file:

```bash
sudo systemctl stop drlink-allocator
sudo mv /var/lib/drlink/registry.json \
  /var/lib/drlink/backups/registry.json.moved-$(date -u +%Y%m%dT%H%M%SZ)
```

Do not `rm` the only copy. The `mv` destination should be under `backups/` with mode `600`:

```bash
sudo chmod 600 /var/lib/drlink/backups/registry.json.moved-*
sudo chown root:root /var/lib/drlink/backups/registry.json.moved-*
```

A later server bootstrap/install with no registry present creates:

```json
{
  "schema_version": 2,
  "reserved": [],
  "clients": {}
}
```

Active listeners in the configured service range are preserved as `reserved` so they are not handed to a new enrollment.

The installer **fails closed** if a v1 or unknown registry is still in place. It will not delete or convert that file automatically.

---

## 6. Apply the current server bootstrap

From the project documentation, install or re-run the current server bootstrap. Deployment-specific values (public host, allocator URL) are entered at install time or supplied as environment variables. They are stored only in `/etc/drlink/config.json`.

Non-interactive example (replace the documentation addresses):

```bash
curl -fsSL https://raw.githubusercontent.com/datarelay-labs/data-relay-link/v2.1.1/dist/bootstrap-server.sh \
| sudo env \
    FRP_PUBLIC_HOST=203.0.113.10 \
    FRP_ALLOCATOR_URL=https://203.0.113.10:6099/enroll \
    bash
```

Interactive install asks for public IP/hostname and allocator URL. It does not use a hard-coded production address.

Re-running the installer reuses existing runtime config when present. It preserves `/etc/frp/server_token`.

---

## 7. Verify frps and the allocator

```bash
sudo drlink status --check
sudo systemctl status drlink-server --no-pager
sudo systemctl status drlink-allocator --no-pager
# Post-install on the server (CA file already exists after install-server.sh):
curl -fsS --cacert /etc/drlink/pki/ca.crt https://127.0.0.1:6099/healthz
```

Expected:

```text
Registry schema : 2
Registry state  : ready
Allocator URL   : configured
Public host     : configured
frps            : active
allocator       : active
```

---

## 8. Create an enrollment

```bash
sudo drlink enrollment create
```

The command prints an enrollment code and a client install one-liner that sets `FRP_ALLOCATOR_URL` via `sudo env`. The enrollment secret is not placed on the command line; the client installer asks for it interactively.

---

## 9. Re-enroll each client

On the remote Linux host, run the command printed by `frp-create-client`. Example shape:

```bash
curl -fsSL https://raw.githubusercontent.com/datarelay-labs/data-relay-link/v2.1.1/dist/bootstrap-client.sh \
| sudo env FRP_ALLOCATOR_URL='https://203.0.113.10:6099/enroll' FRP_ALLOCATOR_CA_SHA256='<sha256>' bash
```

Then enter the enrollment code and add TCP services (SSH is optional).

---

## 10. Verify generic services

On the server:

```bash
sudo frp-clients
sudo frp-client-info <hostname>
```

On the client:

```text
cat /etc/frp/access-info.txt
```

Confirm SSH/HTTP/HTTPS/custom TCP services received persistent public ports.

Schema v2 may also store an optional per-client management public identity (`mgmt_status`, `mgmt_pubkey`, `mgmt_fingerprint`, `mgmt_alg`, `mgmt_mac_key`). That is a compatible field addition; it does not change `schema_version` and must not rewrite service port reservations. Signed management requests use a separate bounded nonce cache (`mgmt-nonces.json`) next to the registry. Entries expire after 15 minutes. Revoking a management identity does not release ports.

---

## If something is still schema v1

Do not force the installer past the error. The expected failure looks like:

```text
ERROR: unsupported registry schema version 1.

This release requires registry schema version 2.

Back up the existing registry and redeploy/reset it explicitly before continuing.
```

Return to step 2 and move the old registry aside before installing again.
