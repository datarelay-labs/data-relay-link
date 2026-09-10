# GitHub upload

This project is published at https://github.com/datarelay-labs/data-relay-link.

Do not commit runtime secrets (`server_token`, enrollment files, `frpc.toml`, `registry.json`, or `access-info.txt`).

From the project directory:

```bash
git init
git branch -M main
git add .
git commit -m "feat: initial Data Relay Link publish"
git remote add origin https://github.com/datarelay-labs/data-relay-link.git
git push -u origin main
```

Then configure the installed server so Zero-Touch enrollment prints the correct client installer command:

```bash
sudo drlink set installer-url \
  https://raw.githubusercontent.com/datarelay-labs/data-relay-link/v2.3.0/dist/bootstrap-client.sh
```

Server one-liner after the repository is pushed:

```bash
curl -fsSL https://raw.githubusercontent.com/datarelay-labs/data-relay-link/v2.3.0/dist/bootstrap-server.sh | sudo bash
```

Client one-liner after the server prints an enrollment (replace the allocator URL with the value from your runtime config):

```bash
curl -fsSL https://raw.githubusercontent.com/datarelay-labs/data-relay-link/v2.3.0/dist/bootstrap-client.sh \
| sudo env DRLINK_ALLOCATOR_URL='https://203.0.113.10:6099/enroll' DRLINK_ALLOCATOR_CA_SHA256='<sha256>' bash
```
