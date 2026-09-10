# Controlled Egress — Operator Guide

> **Product:** Data Relay  
> **Pillar:** Agentless Controlled Egress  
> **CLI:** `sudo drlink` (resource-first; see `docs/CLI_REFERENCE.md`)  
> **Default proxy port:** `6102` (outside published service pool `6000–6098`; not `6080`)

## What it is

Controlled Egress lets hosts on a closed or restricted network reach **only** explicitly approved Internet destinations through a Data Relay Server HTTP/HTTPS forward proxy.

Protected hosts do **not** install Data Relay, frpc, or any agent. They only set a standard proxy:

```bash
export HTTP_PROXY=http://datarelay.example.com:6102
export HTTPS_PROXY=http://datarelay.example.com:6102
```

HTTPS traffic uses `CONNECT` plus TLS ClientHello SNI binding. Application TLS stays end-to-end between the client and the destination. Data Relay does **not** decrypt TLS. Encrypted Client Hello (ECH) is denied.

HTTP destinations use absolute-form `http://` proxy requests and must be listed with `--protocol http`. Mixing protocols on the same host:port is not allowed without an explicit matching protocol entry.

## Quick start (safe create workflow)

Profiles are always created **DISABLED**. Incomplete policies cannot widen egress.

```text
sudo drlink
drlink> egress create ubuntu-update
drlink> egress add-source ubuntu-update 203.0.113.10/32
drlink> egress add-destination ubuntu-update security.ubuntu.com 443 --protocol https
drlink> egress add-destination ubuntu-update archive.ubuntu.com 443 --protocol https
drlink> egress test 203.0.113.10 security.ubuntu.com 443
drlink> egress show ubuntu-update
drlink> egress enable ubuntu-update
```

Then on the closed host, set `HTTP_PROXY` / `HTTPS_PROXY` (or app-specific proxy settings). Verify an allowed destination succeeds and a non-allowed destination is denied.

Compatibility verb-first forms (`create egress-profile`, `show egress-profiles`, …) still run; prefer the resource-first forms above.

## Firewall responsibility

Data Relay never modifies customer firewalls, Security Groups, UFW, iptables, or DNS.

Example customer policy:

```text
ALLOW closed-network → DATA_RELAY_IP:6102
DENY  closed-network → Internet:any
```

## Security model

| Control | Behavior |
|---------|----------|
| Default | DENY |
| Fail closed | Missing/corrupt/invalid policy ⇒ DENY |
| Caller auth | Source IP / CIDR (agentless) |
| Destination | Exact FQDN or strict `*.suffix` + port + **protocol** |
| Protocol | Required `http` or `https` per destination |
| Public Suffix | `*.com` / `*.co.uk`-class wildcards rejected via pinned PSL |
| IP literals | Denied by default |
| DNS | Resolved on the Data Relay server; every candidate IP validated |
| SSRF | Private, loopback, link-local, ULA, metadata (`169.254.169.254`), multicast/reserved denied |
| DNS rebinding | Resolve once → validate → connect to that exact IP |
| Policy reload (Option B) | Gateway reloads `egress-control.json` on mtime change; new authorizations always use current policy |
| Secrets in logs | Proxy-Authorization, cookies, bodies, TLS payloads are not logged |

Inbound Access Control (`access-control.json`) and Egress Control (`egress-control.json`) are **separate policy planes**.

## Public Suffix List

Wildcard destinations are checked against a **pinned** Public Suffix List snapshot:

- Module: `lib/frp_public_suffix.py`
- Data: `lib/data/public_suffix_list.dat` (Mozilla PSL; see module header for VERSION/COMMIT)

Update only from https://publicsuffix.org/list/public_suffix_list.dat and bump the module metadata.

## Windows Update vs Delivery Optimization

Allowlisting Windows Update HTTPS endpoints through Controlled Egress can work when destinations and source CIDRs are explicit. **Delivery Optimization (DO) peer-to-peer / LAN sharing is out of scope** for this proxy: DO may use additional hosts, ports, or non-proxy paths. Prefer WSUS / Microsoft Update over HTTP(S) proxy with a tested destination set, or keep DO disabled on closed hosts that must use the proxy only.

## Process identity

`drlink-egress.service` currently runs as `User=root` with systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`, …). A dedicated non-root service user is **not** the default in this release line.

## Doctor / backup

- `drlink doctor` checks egress policy validity, listen configuration (`6102`), and gateway unit state (read-only).
- After doctor hints, inspect with `drlink egress list` / `drlink egress status`.
- Server backup/restore includes `var/lib/drlink/egress-control.json`.

## Verified client patterns

Exercised in automated tests with a local harness:

- HTTP GET / POST via absolute-form proxy requests (`protocol=http`)
- HTTPS-style `CONNECT` tunnel establishment with SNI binding (`protocol=https`; TLS payload not inspected)

Field apps that speak standard HTTP(S) proxies (`curl`, `wget`, package managers, `git` HTTPS) are expected to work when pointed at the proxy. Validate each app in your environment before production cutover.
