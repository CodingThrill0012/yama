"""Localhost HTTP grant store for experiments.

This is a measurement fixture, not a production control plane. It has no
authentication and is intended to be bound to 127.0.0.1 only. Every
``get`` issues a fresh HTTP request so ``commit_effect`` observes a
remote revocation on the re-check.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from yama.grant import Grant, GrantError, GrantNotFound, GrantStore, GrantStoreError


class RemoteStoreError(GrantStoreError):
    """The HTTP grant store could not complete a request."""


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length < 0 or length > 1_000_000:
        return b""
    return handler.rfile.read(length) if length else b""


def make_supervisor_server(
    directory: Path,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """Return a ThreadingHTTPServer serving a directory-backed GrantStore."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise GrantStoreError(
            f"refusing to bind the experimental supervisor on {host!r}; "
            "use 127.0.0.1, localhost, or ::1"
        )
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    store = GrantStore(directory, readonly=False)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _send(self, code: int, payload: Optional[dict] = None, text: str = "") -> None:
            body = json.dumps(payload).encode("utf-8") if payload is not None else text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json" if payload is not None else "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _grant_id(self) -> Optional[str]:
            parts = self.path.split("?")[0].strip("/").split("/")
            if len(parts) >= 2 and parts[0] == "grants":
                return parts[1]
            return None

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?")[0]
            if path in ("/health", "/"):
                self._send(200, {"status": "ok"})
                return
            grant_id = self._grant_id()
            if not grant_id or path.rstrip("/").endswith("revoke"):
                self._send(404, {"error": "not found"})
                return
            try:
                with lock:
                    grant = store.get(grant_id)
            except GrantNotFound:
                self._send(404, {"error": "not found", "grant_id": grant_id})
                return
            except GrantError as exc:
                self._send(500, {"error": str(exc)})
                return
            self._send(200, grant.to_dict())

        def do_PUT(self) -> None:  # noqa: N802
            grant_id = self._grant_id()
            if not grant_id:
                self._send(404, {"error": "not found"})
                return
            try:
                grant = Grant.from_json(_read_body(self).decode("utf-8"))
            except (GrantError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._send(400, {"error": str(exc)})
                return
            if grant.id != grant_id:
                self._send(400, {"error": "path id and grant id differ"})
                return
            try:
                with lock:
                    store.put(grant)
            except GrantError as exc:
                self._send(500, {"error": str(exc)})
                return
            self._send(200, grant.to_dict())

        def do_POST(self) -> None:  # noqa: N802
            parts = self.path.split("?")[0].strip("/").split("/")
            if len(parts) == 3 and parts[0] == "grants" and parts[2] == "revoke":
                grant_id = parts[1]
                try:
                    with lock:
                        grant = store.revoke(grant_id)
                except GrantNotFound:
                    self._send(404, {"error": "not found", "grant_id": grant_id})
                    return
                except GrantError as exc:
                    self._send(500, {"error": str(exc)})
                    return
                self._send(200, grant.to_dict())
                return
            self._send(404, {"error": "not found"})

    return ThreadingHTTPServer((host, port), Handler)


class SupervisorServer:
    """Background localhost supervisor wrapping make_supervisor_server."""

    def __init__(self, directory: Path, host: str = "127.0.0.1", port: int = 0) -> None:
        self.httpd = make_supervisor_server(directory, host=host, port=port)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        if host == "0.0.0.0":
            host = "127.0.0.1"
        return f"http://{host}:{port}"

    def start(self) -> "SupervisorServer":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class HttpGrantStore:
    """GrantStore-compatible client that re-fetches on every get()."""

    def __init__(self, base_url: str, *, readonly: bool = True, timeout: float = 2.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.readonly = readonly
        self.timeout = timeout

    def _require_writable(self, action: str) -> None:
        if self.readonly:
            raise GrantStoreError(f"store is read-only; only the supervisor may {action}")

    def _request(self, method: str, path: str, body: Optional[str] = None) -> Grant:
        data = None if body is None else body.encode("utf-8")
        request = Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data is not None else {},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8")
        except HTTPError as exc:
            if exc.code == 404:
                grant_id = path.strip("/").split("/")[1] if "/" in path.strip("/") else path
                raise GrantNotFound(grant_id) from exc
            raise RemoteStoreError(f"HTTP {exc.code} for {method} {path}") from exc
        except URLError as exc:
            raise RemoteStoreError(f"cannot reach supervisor at {self.base_url}: {exc}") from exc
        return Grant.from_json(payload)

    def get(self, grant_id: str) -> Grant:
        return self._request("GET", f"/grants/{grant_id}")

    def put(self, grant: Grant) -> None:
        self._require_writable("write grants")
        self._request("PUT", f"/grants/{grant.id}", grant.to_json())

    def revoke(self, grant_id: str) -> Grant:
        self._require_writable("revoke grants")
        return self._request("POST", f"/grants/{grant_id}/revoke")
