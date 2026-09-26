#!/usr/bin/env python3
"""Fresh client with no private CA must still run the advertised Zero-Touch line.

Stock ``curl -fsSL https://host/i/<ticket>`` fails when the enrollment host
presents the project private CA. The advertised command has to succeed on that
same client without --insecure and without a preinstalled CA.
"""
from __future__ import annotations

import hashlib
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import frp_zero_touch as zt  # noqa: E402

TICKET = "AbcdEFghij1234567890ab"


def _openssl(args, **kwargs):
    subprocess.run(
        ["openssl", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **kwargs,
    )


def _make_ca_and_leaf(directory: Path):
    ca_key = directory / "ca.key"
    ca_crt = directory / "ca.crt"
    server_key = directory / "server.key"
    server_csr = directory / "server.csr"
    server_crt = directory / "server.crt"
    ext = directory / "san.cnf"
    _openssl(
        [
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_crt),
            "-days", "2", "-subj", "/CN=drlink-fresh-client-ca",
        ]
    )
    _openssl(
        [
            "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(server_key), "-out", str(server_csr),
            "-subj", "/CN=127.0.0.1",
        ]
    )
    ext.write_text("subjectAltName=IP:127.0.0.1\n", encoding="utf-8")
    _openssl(
        [
            "x509", "-req", "-in", str(server_csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(server_crt), "-days", "2", "-extfile", str(ext),
        ]
    )
    return ca_crt.read_text(encoding="utf-8"), server_crt, server_key


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def main():
    tmp = Path(tempfile.mkdtemp(prefix="drlink-fresh-ca-"))
    httpd = None
    try:
        ca_pem, server_crt, server_key = _make_ca_and_leaf(tmp)
        port = _free_port()
        origin = "https://127.0.0.1:%s" % port
        installer_url = origin + "/artifacts/agent/bootstrap-client.sh"
        installer = (
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            'test -n "${FRP_ALLOCATOR_CA_FILE:-}"\n'
            'test -f "$FRP_ALLOCATOR_CA_FILE"\n'
            'openssl x509 -in "$FRP_ALLOCATOR_CA_FILE" -noout >/dev/null\n'
            "if [[ \"$*\" == *--insecure* || \"$*\" == *curl\\ -k* ]]; then\n"
            "  echo insecure >&2\n"
            "  exit 9\n"
            "fi\n"
            "echo FRESH_CLIENT_TRUST_OK\n"
        )
        digest = hashlib.sha256(installer.encode("utf-8")).hexdigest()
        sums = "%s  agent/bootstrap-client.sh\n" % digest
        script = zt.render_short_url_bootstrap_script(
            origin + "/enroll",
            "ab" * 32,
            "bt1." + ("a" * 16) + "." + ("b" * 64),
            installer_url,
        )
        if "--insecure" in script or "curl -k" in script:
            raise SystemExit("stage-1 script disables TLS verification")
        if "--cacert" not in script or "FRP_ALLOCATOR_CA_FILE" not in script:
            raise SystemExit("same-origin stage-1 script does not pin the private CA")

        bodies = {
            "/i/%s" % TICKET: script.encode("utf-8"),
            "/artifacts/SHA256SUMS": sums.encode("utf-8"),
            "/artifacts/agent/bootstrap-client.sh": installer.encode("utf-8"),
            "/healthz": b"ok\n",
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                path = self.path.split("?", 1)[0]
                body = bodies.get(path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        httpd = HTTPServer(("127.0.0.1", port), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(server_crt), keyfile=str(server_key))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        bare_url = origin + "/i/" + TICKET
        bare = subprocess.run(
            ["curl", "-fsSL", "--proto", "=https", "--tlsv1.2", bare_url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if bare.returncode == 0:
            raise SystemExit("stock curl trusted a private CA; regression is invalid")
        combined = (bare.stderr or "") + (bare.stdout or "")
        if "unable to get local issuer certificate" not in combined.lower():
            raise SystemExit("stock curl failed for a different reason: %s" % combined)

        health = subprocess.run(
            ["curl", "-fsSL", "--proto", "=https", "--tlsv1.2", origin + "/healthz"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if health.returncode == 0:
            raise SystemExit("stock healthz curl trusted a private CA")

        command = zt.private_ca_fresh_client_command(
            "127.0.0.1:%s" % port, TICKET, ca_pem
        )
        if "\n" in command.strip():
            raise SystemExit("advertised command is not one line")
        if "--insecure" in command or "curl -k" in command:
            raise SystemExit("advertised command disables TLS verification")
        if "--cacert" not in command or bare_url not in command:
            raise SystemExit("advertised command does not pin the short URL: %s" % command)
        if not command.startswith("sudo bash -c "):
            raise SystemExit("advertised command is not the sudo one-liner")

        # Execute the displayed command unchanged.
        ran = subprocess.run(
            ["bash", "-lc", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PATH": os.environ.get("PATH", "")},
        )
        output = (ran.stdout or "") + (ran.stderr or "")
        if ran.returncode != 0 or "FRESH_CLIENT_TRUST_OK" not in ran.stdout:
            raise SystemExit(
                "advertised command failed rc=%s\n%s" % (ran.returncode, output)
            )
        if "unable to get local issuer certificate" in output.lower():
            raise SystemExit("advertised command still failed private-CA trust")
        print("FRESH_CLIENT_TRUST_BOOTSTRAP=PASS")
        return 0
    finally:
        if httpd is not None:
            httpd.shutdown()
        subprocess.run(["rm", "-rf", str(tmp)], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
