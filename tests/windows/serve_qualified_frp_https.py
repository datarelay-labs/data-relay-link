#!/usr/bin/env python3
"""Hermetic HTTPS fixture serving the vendored Windows FRP zip.

Exercises the qualified server-local artifact contract:
  https://<origin>/artifacts/frp/<ver>/frp_<ver>_windows_amd64.zip

Does not change product download semantics; CI smoke pins the ephemeral CA
and points FRP_ALLOCATOR_URL at this loopback origin.
"""
from __future__ import annotations

import argparse
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib"))
import frp_pki  # noqa: E402


def _default_zip(ver: str) -> Path:
    return ROOT / "third_party" / "frp" / ("v" + ver) / "binaries" / (
        "frp_%s_windows_amd64.zip" % ver
    )


def _pem_to_der(pem_bytes: bytes) -> bytes:
    return ssl.PEM_cert_to_DER_cert(pem_bytes.decode("ascii"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frp-version", default="0.71.0")
    parser.add_argument("--zip-path", default="")
    parser.add_argument("--pki-dir", required=True)
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    args = parser.parse_args(argv)

    ver = args.frp_version.strip()
    zip_path = Path(args.zip_path) if args.zip_path else _default_zip(ver)
    if not zip_path.is_file():
        sys.stderr.write("ERROR: qualified Windows FRP zip missing: %s\n" % zip_path)
        return 2

    pki = frp_pki.ensure_pki(args.pki_dir, args.bind)
    # DER CA for Windows PowerShell 5.1 X509Certificate2 pin path.
    ca_der_path = Path(args.pki_dir) / "ca.der"
    ca_der_path.write_bytes(_pem_to_der(Path(pki["ca_crt"]).read_bytes()))
    artifact_path = "/artifacts/frp/%s/%s" % (ver, zip_path.name)
    payload = zip_path.read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.split("?", 1)[0] != artifact_path:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):  # noqa: A003
            return

    httpd = ThreadingHTTPServer((args.bind, 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki["server_crt"], pki["server_key"])
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    origin = "https://%s:%d" % (args.bind, port)

    status = Path(args.status_file)
    status.write_text(
        "\n".join(
            [
                "ORIGIN=%s" % origin,
                "PORT=%d" % port,
                "CA_CRT=%s" % pki["ca_crt"],
                "CA_DER=%s" % ca_der_path,
                "ARTIFACT_PATH=%s" % artifact_path,
                "ZIP_PATH=%s" % zip_path,
                "",
            ]
        ),
        encoding="utf-8",
    )

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
