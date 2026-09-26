# Data Relay Link — Installation

> **Status:** v2.4 development operator guide
> **Authority:** Product semantics are defined by `PRODUCT_MASTER.md` and the CLI/AI Master. Release provenance rules are defined by `VERSION_POLICY.md`.

## 1. Installation model

Data Relay Link has two runtime roles:

```text
DRLink Server
DRLink Agent Host
```

The Server is Linux-based. Agent Hosts are supported on the platforms qualified by the current release evidence.

The normal operator interface after installation is:

```bash
sudo drlink
```

## 2. Source identity before stable release

Until an immutable `v2.4.0` tag exists, do not install from a future tag, mutable `main`, or an unqualified `latest` path.

Development/pre-release installation uses an exact immutable Git SHA or an explicitly qualified candidate artifact.

Conceptual exact-SHA bootstrap:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/datarelay-labs/datarelay-link/<EXACT_SHA>/dist/bootstrap-server.sh \
  | sudo bash
```

The exact SHA must be the candidate or source-preparation HEAD that the operator intends to test.

Stable installation may use the immutable stable tag only after that tag and its qualified artifacts actually exist.

## 3. Server installation result

After installation, verify with read-only commands:

```text
show version
show status
system diagnostics
```

Expected identity includes:

```text
Data Relay Link product version
release channel
exact Source HEAD
Relay Engine (FRP) version
role = DRLink Server
```

A development build must not identify itself as stable.

## 4. Public identity and hostname

Server control/allocator identity and optional friendly hostnames are distinct.

```text
public_ip / public_host
→ control / allocator identity

public_hostname
→ optional published Remote Service alias

bootstrap_hostname
→ Zero-Touch bootstrap hostname
```

If installation allows a domain to be selected as the product public identity, that choice must be used consistently by generated bootstrap/Zero-Touch links and other user-facing URLs according to current implementation.

Changing a friendly published-service hostname must not silently change management identity.

## 5. Connect a Managed Host

On the DRLink Server:

```text
set enrollment zero-touch
```

The guided workflow issues a one-time enrollment/install credential.

Ticket limits:

```text
maximum per request           10
maximum active unused         10
default TTL                   1 hour
maximum TTL                   24 hours
use count                     1
```

Raw ticket/install URL material is shown only at issuance. Server persistent state retains verifier/hash plus lifecycle metadata, not a redisplayable raw ticket.

## 6. Agent verification

After successful enrollment, on the Agent Host verify:

```text
show status
show agent
system info
system diagnostics
```

The role must be shown as `Agent Host`.

## 7. Create connectivity

Remote Service creation occurs on the owning Agent Host.

Example:

```text
set remote-service ssh-access
```

or complete one-shot form:

```text
set remote-service ssh-access destination this-host service ssh enabled
```

Remote Access policy is configured on the Server and is independent from Remote Service creation.

## 8. External infrastructure boundary

Data Relay Link does not silently create or modify:

- cloud security groups;
- customer firewall/NAT/DNAT rules;
- DNS-provider records;
- OS users/passwords;
- SSH server configuration;
- application TLS certificates.

Those prerequisites remain operator/environment responsibility unless an explicitly approved future product feature says otherwise.

## 9. Installation validation

A production candidate is not considered installed/qualified merely because bootstrap exits successfully.

At minimum verify:

```text
product identity
role
service health
management identity
Zero-Touch/enrollment
Remote Service lifecycle
policy behavior
reboot persistence
uninstall/reinstall where required by the release gate
```

Use `RELEASE_VALIDATION.md` and the exact release checklist for candidate qualification.
