# GitHub upload

This project is published at https://github.com/datarelay-labs/datarelay-link.

Do not commit runtime secrets (`server_token`, enrollment files, `frpc.toml`, `registry.json`, or `access-info.txt`).

From the project directory:

```bash
git init
git branch -M main
git add .
git commit -m "feat: initial Data Relay Link publish"
git remote add origin https://github.com/datarelay-labs/datarelay-link.git
git push -u origin main
```

Then configure the installed server so Zero-Touch enrollment prints the correct client installer command.

The published prior stable is immutable tag `v2.3.0`. `v2.2.1` is an older published release. `v2.3.1` was not manufactured. There is no stable `v2.4.0` tag yet. Until that tag exists, candidate installs use an exact 40-character commit SHA. A future tag URL such as `v2.4.0/dist/bootstrap-server.sh` would 404 until the tag is created. Do not install from mutable `main`.

Stable baseline:

```bash
sudo drlink set installer-url \
  https://raw.githubusercontent.com/datarelay-labs/datarelay-link/v2.3.0/dist/bootstrap-client.sh
```

Development candidate (replace `<40-char-sha>` with the exact commit):

```bash
sudo drlink set installer-url \
  https://raw.githubusercontent.com/datarelay-labs/datarelay-link/<40-char-sha>/dist/bootstrap-client.sh
```

Server one-liner for the documented stable baseline:

```bash
curl -fsSL https://raw.githubusercontent.com/datarelay-labs/datarelay-link/v2.3.0/dist/bootstrap-server.sh | sudo bash
```

Candidate server install:

```bash
curl -fsSL https://raw.githubusercontent.com/datarelay-labs/datarelay-link/<40-char-sha>/dist/bootstrap-server.sh | sudo bash
```

Client one-liner after the server prints an enrollment (replace the allocator URL with the value from your runtime config, and use the same immutable ref as the server install):

```bash
curl -fsSL https://raw.githubusercontent.com/datarelay-labs/datarelay-link/<40-char-sha>/dist/bootstrap-client.sh \
| sudo env DRLINK_ALLOCATOR_URL='https://203.0.113.10:6099/enroll' DRLINK_ALLOCATOR_CA_SHA256='<sha256>' bash
```
