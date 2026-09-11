# Zero-Touch Short URL (Option B)

Additive Zero-Touch UX after v2.1.2. When an operator configures a publicly
trusted bootstrap hostname and reverse proxy, enrollment can use:

```bash
curl -fsSL https://bootstrap.example.com/i/<opaque-ticket> | sudo bash
```

When `bootstrap_hostname` is unset, the v2.1.2 transitional command remains:

```bash
curl -fsSL <immutable-installer> | sudo bash -s -- 'zt1.<opaque>'
```

## Trust boundary

```text
Client
   |
   | publicly trusted HTTPS (stock OS trust)
   v
Operator reverse proxy (Caddy / nginx / LB)
   |
   | private / loopback upstream
   v
Data Relay Link allocator
   |
   +-- GET  /i/<opaque>          generic bootstrap script (no ticket consume)
   +-- GET  /ca.crt              Private CA certificate (existing)
   +-- POST /bootstrap/redeem    first-machine bind (existing)
   +-- POST /enroll              enrollment (existing)

after enrollment:

Client
   |
   | existing Data Relay Link Private CA
   v
Management plane
```

Data Relay Link does **not** issue, renew, or store the public bootstrap
certificate. The operator owns DNS, public TLS, and the reverse proxy.

## Configuration

```bash
sudo drlink server set bootstrap-hostname bootstrap.example.com
sudo drlink server unset bootstrap-hostname
sudo drlink server status
```

`bootstrap_hostname` is separate from `public_hostname`:

| Field | Meaning |
|---|---|
| `public_hostname` | Published-service access alias (`ssh -p 6000 user@fw.example.com`) |
| `bootstrap_hostname` | Public TLS Zero-Touch short URL entry hostname |

Setting `bootstrap_hostname` does **not** create DNS records, open firewall
ports, configure NAT, invoke ACME, or restart FRP services.

## Operator responsibilities

1. Create DNS for the bootstrap hostname
2. Terminate publicly trusted HTTPS on an operator reverse proxy
3. Renew the public certificate
4. Proxy only the required allocator paths (see below)

## Data Relay Link responsibilities

1. Serve `GET /i/<opaque-ticket>`
2. Validate tickets without consuming them on GET
3. Keep Enrollment Profile server-side
4. Preserve Private CA redeem/enroll flow
5. Prefer short URL command generation when configured
6. Keep `zt1` / legacy env / manual enrollment working

## Minimum public proxy allowlist

Do **not** proxy `/` wholesale to the allocator.

Required for short-URL bootstrap delivery:

```text
GET /i/<opaque-ticket>
```

Required for the reused enrollment protocol (when clients reach the allocator
through the same public edge, for example private-IP / NAT deployments):

```text
GET  /ca.crt
POST /bootstrap/redeem
POST /enroll
```

Optional health check:

```text
GET /healthz
```

In Direct mode with a publicly reachable allocator (`IP:6099` or equivalent),
the reverse proxy may expose **only** `/i/` and leave redeem/enroll on the
existing Private CA allocator URL embedded in the bootstrap script.

### nginx example

The `/i/<ticket>` path contains a short-lived credential. The copy/paste default
below turns **off** access logging for that location so the raw URI never hits
operator access logs. (Alternatively, an explicitly verified sanitized log
format that rewrites `/i/...` to `/i/<redacted>` is acceptable.)

```nginx
server {
    listen 443 ssl http2;
    server_name bootstrap.example.com;

    # Operator-managed publicly trusted certificate
    ssl_certificate     /etc/ssl/bootstrap.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/bootstrap.example.com/privkey.pem;

    location ~ ^/i/[^/?#]+$ {
        # Required default: do not log the raw /i/<ticket> credential URL.
        access_log off;
        proxy_pass https://127.0.0.1:6099;
        proxy_ssl_verify off;   # upstream is project Private CA on loopback
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # Include these only when the public edge also fronts redeem/enroll:
    location = /ca.crt {
        proxy_pass https://127.0.0.1:6099;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
    }
    location = /bootstrap/redeem {
        proxy_pass https://127.0.0.1:6099;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
    location = /enroll {
        proxy_pass https://127.0.0.1:6099;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location / {
        return 404;
    }
}
```

### Caddy example

If the operator enables Caddy access logging, `/i/<ticket>` **must** be excluded
or redacted. The complete short URL is a short-lived credential; raw URI logging
at the operator edge defeats allocator-side redaction. Data Relay Link does not
manage the reverse proxy — access-log policy remains an operator responsibility.

```caddy
bootstrap.example.com {
    @short_url path_regexp i ^/i/[^/?#]+$
    @allowed {
        path_regexp i ^/i/[^/?#]+$
        path /ca.crt /bootstrap/redeem /enroll /healthz
    }
    # When access logging is enabled, skip or redact @short_url so the ticket
    # never appears in operator logs. Do not log the raw request URI for /i/.
    handle @allowed {
        reverse_proxy https://127.0.0.1:6099 {
            transport http {
                tls_insecure_skip_verify
            }
        }
    }
    handle {
        respond 404
    }
}
```

`tls_insecure_skip_verify` applies only to the operator proxy's **loopback**
upstream to the Private CA allocator. Clients still use stock OS trust to the
public bootstrap hostname. Do not put `curl -k` in client bootstrap commands.


## Ticket lifecycle

```text
GET /i/<ticket>          → no consume, no machine bind
POST /bootstrap/redeem   → first-machine bind
POST /enroll success     → completed_at (single-use)
```

Treat `/i/<opaque-ticket>` as sensitive until used, expired, or revoked.

## v2.1.3 Real E2E evidence

Recorded Short URL Real E2E (public TLS via operator edge / cloudflared) against
production-equivalent tree `091f9a99b5e8d648099da97457781bcd24980142`. Candidate
`011c8aaa3be833ea411546002f1d4579953a7b86` differs only in tests, docs, version
metadata, release metadata, and checksums — not Short URL production behavior.
Evidence reused by code equivalence; Real E2E was not re-run solely for the
metadata bump.

```text
RELEASE=2.1.3
BASELINE_LINUX=PASS
AMAZON_LINUX_2023=PASS
ROCKY_LINUX_8_10=PASS
PUBLIC_TLS_STOCK_OS_TRUST=PASS
SHORT_URL_GENERATION=PASS
ZERO_TOUCH_ENROLLMENT=PASS
FIRST_MACHINE_BINDING=PASS (automated suite; not in Real E2E harness)
TICKET_SINGLE_USE=PASS (automated suite; not in Real E2E harness)
MULTI_SERVICE=PASS (automated suite; Real E2E used --ssh profile)
MANAGEMENT_ONLY=PASS (automated suite; not in Real E2E harness)
REBOOT_RECONNECT=PASS
INVALID_TLS_FAIL_CLOSED=PASS
ZT1_FALLBACK=PASS
TESTED_PRODUCTION_HEAD=091f9a99b5e8d648099da97457781bcd24980142
CANDIDATE_HEAD=40bc05967ebfd93c3723a8edff206967c4711c35
EVIDENCE_REUSED_BY_CODE_EQUIVALENCE=YES
EVIDENCE_DIRS=
  e2e-reports/short-url-e2e-20260904T153344Z (baseline-linux)
  e2e-reports/short-url-e2e-20260904T153050Z (amazon-linux-2023)
  e2e-reports/short-url-e2e-20260904T153202Z (rocky-linux-8.10)
```

Unit/Docker suite PASS is not a substitute for the Real E2E platform rows above.

## single-443 note

Do **not** replace the Private CA leaf used by `/~!frp` / WSS. Public TLS for
bootstrap terminates on the **operator** reverse proxy. The in-project
single-443 frontend allowlist may forward `/i/...` to the allocator when an
outer edge proxies into it, but that frontend continues to present the project
Private CA identity.

## Failure behavior

If the bootstrap public certificate is invalid/expired/untrusted:

- short URL fetch fails closed under stock OS trust
- no Client is created
- ticket is not completed
- management plane is unaffected
- `zt1` fallback still works
