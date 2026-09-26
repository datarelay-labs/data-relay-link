# pfSense / Firewall DNAT example

The addresses below are RFC documentation examples. Replace them with your firewall and internal FRP server addresses.

This example matches a NAT deployment where public ports differ from local listen ports. Matching public/listen values (for example 443/443 and 6099/6099) are also valid; they are convenience defaults, not requirements.

Example topology:

- Public firewall IP: `203.0.113.10`
- Internal FRP server: `192.0.2.50`
- FRP control: public TCP/8443 -> internal listen TCP/443
- Allocator HTTPS: public TCP/9443 -> internal listen TCP/6099
- Data Relay Link Remote Services: TCP/6000-6098, 1:1 public/internal port numbers

Create three DNAT / Port Forward rules:

1. `203.0.113.10:8443` -> `192.0.2.50:443`
2. `203.0.113.10:9443` -> `192.0.2.50:6099`
3. `203.0.113.10:6000-6098` -> `192.0.2.50:6000-6098`

For the range rule in pfSense, set the redirect target port to the beginning of the range (`6000`). pfSense calculates the ending port automatically.

The allocator URL that clients use must be HTTPS, for example `https://203.0.113.10:9443/enroll`. Do not publish a plain HTTP enrollment endpoint.

Restrict the public service-port range by source IP where practical. The enrollment endpoint uses a short-lived HMAC-authenticated enrollment code over verified HTTPS, but firewall rate limiting/source restrictions are still recommended.
