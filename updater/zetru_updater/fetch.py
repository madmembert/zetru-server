"""HTTPS downloads restricted to the hosts named in the manifest. Redirects are refused, the size is capped
while streaming, and conditional requests (ETag / Last-Modified) avoid re-downloading unchanged feeds."""

from __future__ import annotations

import hashlib
import http.client
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

USER_AGENT = "zetru-updater/1.0"
TIMEOUT_S = 60


class FetchError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FetchError("redirect_refused")


@dataclass
class FetchResult:
    status: str                  # downloaded | not_modified
    path: str | None
    size: int
    etag: str | None
    last_modified: str | None


def build_opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Standard proxy variables (HTTPS_PROXY) are honoured: they are operator configuration, and a proxy
    # still only receives CONNECT requests for the allow-listed hosts.
    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))


def allowed_hosts(urls: list[str]) -> set[str]:
    return {urllib.parse.urlsplit(u).hostname for u in urls}


def fetch(url: str, dest_dir: str, hosts: set[str], max_bytes: int, etag: str | None = None,
          last_modified: str | None = None, opener=None) -> FetchResult:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in hosts:
        raise FetchError("host_not_allowed")
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(url, headers=headers)
    opener = opener or build_opener()
    try:
        response = opener.open(request, timeout=TIMEOUT_S)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return FetchResult("not_modified", None, 0, etag, last_modified)
        raise FetchError(f"http_{exc.code}") from None
    except (urllib.error.URLError, OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        raise FetchError(type(exc).__name__) from None
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, "download-" + hashlib.sha256(url.encode()).hexdigest()[:16])
    size = 0
    try:
        with response, open(path, "wb") as out:
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FetchError("too_large")
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise FetchError("too_large")
                out.write(chunk)
            # http.client does not raise when a Content-Length body ends early: check it here, a truncated
            # list would otherwise be published as if it were complete.
            if declared and declared.isdigit() and size != int(declared):
                raise FetchError("truncated")
    except FetchError:
        os.unlink(path)
        raise
    except (OSError, http.client.HTTPException, ValueError) as exc:
        if os.path.exists(path):
            os.unlink(path)
        raise FetchError(type(exc).__name__) from None
    return FetchResult("downloaded", path, size, response.headers.get("ETag"), response.headers.get("Last-Modified"))
