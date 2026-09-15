# Controlled Egress — Operator Guide

> **Product family:** Data Relay
>
> **Pillar:** Agentless Controlled Egress (sibling of Secure Remote Access / Data Relay Link inbound)
>
> **CLI:** `sudo drlink` (action-first; see `docs/CLI_REFERENCE.md`)
>
> **Default HTTP/HTTPS proxy port:** `6102` (outside published service pool `6000–6098`; not `6080`)
>
> **Fixed TCP Egress listen pool:** `6200–6299`

## What it is

Controlled Egress lets hosts on a closed or restricted network reach **only** explicitly approved Internet destinations through a Data Relay Server:

- **HTTP/HTTPS forward proxy** (agentless; clients set `HTTP_PROXY` / `HTTPS_PROXY`)
- **Fixed TCP Egress** (proxy-unaware apps connect to a server-owned listener that relays to one preconfigured FQDN:port)

Protected hosts do **not** install Data Relay, frpc, or any agent for HTTP/HTTPS mode. They only set a standard proxy:

```bash
export HTTP_PROXY=http://datarelay.example.com:6102
export HTTPS_PROXY=http://datarelay.example.com:6102
```

HTTPS traffic uses `CONNECT` plus TLS ClientHello SNI binding. Application TLS stays end-to-end between the client and the destination. Data Relay does **not** decrypt TLS. Encrypted Client Hello (ECH) is denied.

HTTP destinations use absolute-form `http://` proxy requests and must be listed
with protocol HTTP in the guided destination flow (or the matching backend
protocol when using internal tools). Mixing protocols on the same host:port is
not allowed without an explicit matching protocol entry.

## Quick start (safe create workflow)

Profiles are always created **DISABLED**. Incomplete policies cannot widen egress.

```text
sudo drlink
drlink> set internet-profile ubuntu-update
drlink> set internet-source ubuntu-update 10.0.0.0/24
drlink> set internet-destination ubuntu-update archive.ubuntu.com 443 https
drlink> test internet 10.0.0.5 archive.ubuntu.com 443 https
drlink> show internet-profile ubuntu-update
drlink> set internet-profile ubuntu-update enabled
```

`set internet-source` / `set internet-destination` collect CIDR, FQDN, port, and
protocol through guided prompts when incomplete (no public `--options`).
`test internet` previews policy + DNS safety only: **no live connect**,
**no state mutation**.

Then on the closed host, set `HTTP_PROXY` / `HTTPS_PROXY` (or app-specific proxy settings). Verify an allowed destination succeeds and a non-allowed destination is denied.

### Fixed TCP Egress (proxy-unaware apps)

Each Fixed TCP relay pins **one** listener to **one** exact destination FQDN:port. The connecting client cannot choose destination host, IP, or port.

```text
sudo drlink
drlink> set fixed-tcp vendor-license
# follow guided Fixed TCP prompts, then:
drlink> set fixed-tcp vendor-license enabled
```

Relays are always created **DISABLED**. Listen ports auto-allocate from **6200–6299** unless the operator chooses a listen port in the guided flow. Runtime: `drlink-tcp-egress.service`.

### Templates (never auto-enable)

```text
drlink> show internet
drlink> show internet-templates
drlink> set internet-profile my-api template <TEMPLATE>
# then set sources if needed, test, enable
```

Older `egress*` / `recipe` forms may still run as hidden compatibility aliases.
They are not the advertised CLI.

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
| Protocol | Required `http`, `https`, or `tcp` per destination |
| Public Suffix | `*.com` / `*.co.uk`-class wildcards rejected via pinned PSL (HTTP/HTTPS); Fixed TCP is exact FQDN only |
| IP literals | Denied by default |
| DNS | Resolved on the Data Relay server; every candidate IP validated; mixed public+unsafe ⇒ DENY ALL |
| SSRF | Private, loopback, link-local, ULA, metadata (`169.254.169.254`), multicast/reserved denied |
| DNS rebinding | Resolve once → validate → connect to that exact IP (no DNS re-resolution at connect) |
| Fixed TCP | Client cannot negotiate destination; one relay = one FQDN:port |
| Policy reload (Option B) | Gateway/TCP runtime reload `egress-control.json` on mtime change; new authorizations always use current policy |
| Secrets in logs | Proxy-Authorization, cookies, bodies, TLS/TCP payloads are not logged |

Inbound Access Control (`access-control.json`) and Egress Control (`egress-control.json`) are **separate policy planes**.

## Public Suffix List

Wildcard destinations are checked against a **pinned** Public Suffix List snapshot:

- Module: `lib/frp_public_suffix.py`
- Data: `lib/data/public_suffix_list.dat` (Mozilla PSL; see module header for VERSION/COMMIT)

Update only from https://publicsuffix.org/list/public_suffix_list.dat and bump the module metadata.

## Windows Update vs Delivery Optimization

Allowlisting Windows Update HTTPS endpoints through Controlled Egress can work when destinations and source CIDRs are explicit. **Delivery Optimization (DO) peer-to-peer / LAN sharing is out of scope** for this proxy: DO may use additional hosts, ports, or non-proxy paths. Prefer WSUS / Microsoft Update over HTTP(S) proxy with a tested destination set, or keep DO disabled on closed hosts that must use the proxy only.

## Process identity

`drlink-egress.service` (HTTP/HTTPS) and `drlink-tcp-egress.service` (Fixed TCP) run as dedicated user `drlink-egress` (non-root) with
systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`, …). Parent
directories are traversed with least privilege; registry/enrollment secrets
remain root-owned and are not writable by the egress account.

## Diagnostics / backup

- `drlink system diagnostics` checks Internet Access / egress policy validity, HTTP listen (`6102`), Fixed TCP listeners (`6200–6299`), and gateway/TCP unit state (read-only).
- After diagnostics hints, inspect with `show internet-profiles` / `show internet` / `test internet`.
- Server backup/restore includes `var/lib/drlink/egress-control.json` (profiles + Fixed TCP relays).

## Verified client patterns

Exercised in automated tests with a local harness:

- HTTP GET / POST via absolute-form proxy requests (`protocol=http`)
- HTTPS-style `CONNECT` tunnel establishment with SNI binding (`protocol=https`; TLS payload not inspected)
- Fixed TCP relay to an echo/TCP service (`protocol=tcp`; destination pinned)

Field apps that speak standard HTTP(S) proxies (`curl`, `wget`, package managers, `git` HTTPS) are expected to work when pointed at the proxy. Proxy-unaware TCP apps use Fixed TCP listeners. Validate each app in your environment before production cutover.
