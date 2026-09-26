#!/usr/bin/env python3
"""Loopback HTTPS server for Windows FRP binary smoke (no OpenSSL CLI)."""
from __future__ import annotations

import argparse
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip-path", required=True)
    parser.add_argument("--artifact-path", required=True)
    parser.add_argument("--cert-pem", required=True)
    parser.add_argument("--key-pem", required=True)
    parser.add_argument("--status-file", required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--origin-host", default="localhost")
    args = parser.parse_args(argv)

    zip_path = Path(args.zip_path)
    if not zip_path.is_file():
        sys.stderr.write("ERROR: zip missing: %s\n" % zip_path)
        return 2
    payload = zip_path.read_bytes()
    artifact = args.artifact_path if args.artifact_path.startswith("/") else "/" + args.artifact_path

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path != artifact:
                self.send_error(404, "path=%s expected=%s" % (path, artifact))
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
    ctx.load_cert_chain(args.cert_pem, args.key_pem)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    origin = "https://%s:%d" % (args.origin_host, port)
    Path(args.status_file).write_text(
        "ORIGIN=%s\nPORT=%d\nARTIFACT_PATH=%s\n" % (origin, port, artifact),
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
