# Controlled Egress — Operator Guide

> **Product:** Data Relay  
> **Pillar:** Agentless Controlled Egress  
> **CLI:** `sudo drlink`  
> **Default proxy port:** `6080`

## What it is

Controlled Egress lets hosts on a closed or restricted network reach **only** explicitly approved Internet destinations through a Data Relay Server HTTP/HTTPS forward proxy.

Protected hosts do **not** install Data Relay, frpc, or any agent. They only set a standard proxy:

```bash
export HTTP_PROXY=http://datarelay.example.com:6080
export HTTPS_PROXY=http://datarelay.example.com:6080
```

HTTPS traffic uses `CONNECT`. Application TLS stays end-to-end between the client and the destination. Data Relay does **not** decrypt TLS in v1.

## Quick start

1. Install / update the Data Relay server (existing `install-server.sh` / project update).
2. On the firewall, allow closed-network hosts to reach `DATA_RELAY_IP:6080` only. Do **not** open general Internet egress from those hosts.
3. Create an Egress Profile:

```text
sudo drlink
drlink> create egress-profile ubuntu-update
drlink> add egress-profile ubuntu-update destination security.ubuntu.com 443
drlink> add egress-profile ubuntu-update destination archive.ubuntu.com 443
drlink> add egress-profile ubuntu-update source 203.0.113.10/32
drlink> show egress-profile ubuntu-update
```

4. On the closed host, set `HTTP_PROXY` / `HTTPS_PROXY` (or app-specific proxy settings).
5. Verify an allowed destination succeeds and a non-allowed destination is denied.

## Firewall responsibility

Data Relay never modifies customer firewalls, Security Groups, UFW, iptables, or DNS.

Example customer policy:

```text
ALLOW closed-network → DATA_RELAY_IP:6080
DENY  closed-network → Internet:any
```

## Security model (v1)

| Control | Behavior |
|---------|----------|
| Default | DENY |
| Fail closed | Missing/corrupt/invalid policy ⇒ DENY |
| Caller auth | Source IP / CIDR (agentless) |
| Destination | Exact FQDN or strict `*.suffix` + port |
| IP literals | Denied by default |
| DNS | Resolved on the Data Relay server; every candidate IP validated |
| SSRF | Private, loopback, link-local, ULA, metadata (`169.254.169.254`), multicast/reserved denied |
| DNS rebinding | Resolve once → validate → connect to that exact IP |
| Secrets in logs | Proxy-Authorization, cookies, bodies, TLS payloads are not logged |

Inbound Access Control (`access-control.json`) and Egress Control (`egress-control.json`) are **separate policy planes**.

## Known v1 limitations

- Multiple hosts behind the same NAT appear as one source IP (site/network policy, not per-host identity).
- No TLS Proxy endpoint, mTLS, TLS inspection, SOCKS5, PAC, SWG/SASE features, or automatic firewall/DNS changes.
- Plaintext proxy credentials are **not** the primary security boundary.

## Doctor / backup

- `drlink doctor` checks egress policy validity, listen configuration, and gateway unit state (read-only).
- Server backup/restore includes `var/lib/drlink/egress-control.json`.

## Verified client patterns

Exercised in automated tests with a local harness:

- HTTP GET / POST via absolute-form proxy requests
- HTTPS-style `CONNECT` tunnel establishment (TLS payload not inspected)

Field apps that speak standard HTTP(S) proxies (`curl`, `wget`, package managers, `git` HTTPS) are expected to work when pointed at the proxy. Validate each app in your environment before production cutover.
