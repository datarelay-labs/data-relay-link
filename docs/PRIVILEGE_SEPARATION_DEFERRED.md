# Privilege separation hardening (deferred)

This is a current deferred design and operations record for the v2.4.0
development target and later. It is not a v2.3.1 release plan. v2.3.1 was
not manufactured.

Correctness blockers (egress create contract, destructive selector TOCTOU,
dual-role uninstall, allocator TLS handshake, lifecycle docs) take priority
over introducing new dedicated system users for access/frpc/frps/allocator.

Decision:

```text
ROOT_PRIVILEGE_HARDENING=DEFERRED_WITH_REASON
```

Reason:

Narrowing systemd User=/CapabilityBoundingSet= for drlink-access,
drlink-client (frpc), drlink-server (frps), and the allocator requires
platform-specific installer compatibility validation (Amazon Linux 2 and
older systemd) plus dual-role file ownership audits. Shipping that during
v2.4.0 qualification risks installer/runtime instability for the 1–50 client
target without changing the product contract.

Post-v2.4 follow-up:

- dedicated drlink-access user with narrow write paths
- unprivileged frpc account when supported targets allow
- frps with CAP_NET_BIND_SERVICE only if privileged bind is required
- allocator read-only config/PKI with narrow registry/enrollment write
