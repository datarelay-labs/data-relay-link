#!/usr/bin/env python3
"""Bounded ThreadingMixIn — acquire concurrency slot BEFORE spawning a worker.

ThreadingHTTPServer / ThreadingTCPServer spawn a thread in process_request()
before the handler runs. A semaphore taken inside do_GET/do_POST therefore
does not bound thread creation.

Use BoundedThreadingMixIn (or wrap process_request) so the limit is real.
"""
from __future__ import annotations

import socket
import threading
from typing import Optional


class BoundedThreadingMixIn:
    """ThreadingMixIn variant with an accept-time concurrency gate.

    Subclasses must set:
      - max_concurrent: int
      - request_timeout: float (idle/read timeout applied to accepted sockets)

    Optional:
      - reject_callback(request, client_address) for overload response
    """

    daemon_threads = True
    block_on_close = False
    max_concurrent = 32
    request_timeout = 30.0
    reject_callback = None

    def __init__(self, *args, **kwargs):
        self._slot_sem = threading.BoundedSemaphore(int(self.max_concurrent))
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # Apply idle/read timeout before any worker starts.
        try:
            request.settimeout(float(self.request_timeout))
        except (OSError, AttributeError):
            pass
        acquired = self._slot_sem.acquire(blocking=False)
        if not acquired:
            try:
                cb = getattr(self, "reject_callback", None)
                if callable(cb):
                    cb(request, client_address)
            except Exception:
                pass
            try:
                request.close()
            except OSError:
                pass
            return

        def run():
            try:
                self.finish_request(request, client_address)
            except Exception:
                try:
                    self.handle_error(request, client_address)
                finally:
                    try:
                        self.shutdown_request(request)
                    except Exception:
                        pass
            else:
                try:
                    self.shutdown_request(request)
                except Exception:
                    pass
            finally:
                self._slot_sem.release()

        t = threading.Thread(target=run)
        t.daemon = self.daemon_threads
        t.start()


def close_quietly(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass
