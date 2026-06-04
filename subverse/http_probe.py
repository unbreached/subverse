"""Per-host HTTP + TLS probe.

For each hostname we try HTTPS first (with full certificate verification), then
fall back to HTTP. We record the final status code, the Server header, the final
URL after redirects, and — crucially for the map — whether TLS verified cleanly
or failed (expired / self-signed / hostname mismatch / untrusted CA = "insecure
TLS"). Runs across a thread pool.
"""

from __future__ import annotations

import concurrent.futures
import socket
import ssl
import urllib.error
import urllib.request

_UA = "Subverse/0.1 (+attack-surface map; authorized assessment)"


def _open(url: str, ctx: ssl.SSLContext | None, timeout: float):
    """Return (status, server, final_url). Raises on transport errors."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
    handlers = []
    if ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    try:
        resp = opener.open(req, timeout=timeout)
        status = resp.status
        server = resp.headers.get("Server", "")
        final = resp.geturl()
        resp.close()
        return status, server, final
    except urllib.error.HTTPError as e:
        # 4xx/5xx still tell us the host is alive and serving
        return e.code, e.headers.get("Server", "") if e.headers else "", e.url or url


def probe_host(host: str, timeout: float = 6.0) -> dict:
    out = {
        "reachable": False, "http_status": 0, "http_via": "",
        "http_server": "", "http_final": "", "tls_ok": None, "tls_issue": "",
    }
    verify_ctx = ssl.create_default_context()
    insecure_ctx = ssl.create_default_context()
    insecure_ctx.check_hostname = False
    insecure_ctx.verify_mode = ssl.CERT_NONE

    # --- HTTPS, verified ---
    https_conn_ok = False
    try:
        status, server, final = _open(f"https://{host}/", verify_ctx, timeout)
        out.update(reachable=True, http_status=status, http_via="https",
                   http_server=server, http_final=final, tls_ok=True)
        return out
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            out["tls_ok"] = False
            out["tls_issue"] = _tls_reason(reason)
            https_conn_ok = True
        elif isinstance(reason, ssl.SSLError):
            out["tls_ok"] = False
            out["tls_issue"] = str(getattr(reason, "reason", reason)) or "TLS error"
            https_conn_ok = True
        # else: connection refused / timeout / DNS — fall through to retry/HTTP
    except (socket.timeout, TimeoutError, ConnectionError, OSError):
        pass

    # --- HTTPS, ignoring cert (only if the TLS layer was reachable) ---
    if https_conn_ok:
        try:
            status, server, final = _open(f"https://{host}/", insecure_ctx, timeout)
            out.update(reachable=True, http_status=status, http_via="https",
                       http_server=server, http_final=final)
            return out
        except (urllib.error.URLError, socket.timeout, TimeoutError,
                ConnectionError, OSError):
            pass

    # --- plain HTTP ---
    try:
        status, server, final = _open(f"http://{host}/", None, timeout)
        out.update(reachable=True, http_status=status, http_via="http",
                   http_server=server, http_final=final)
        if out["tls_ok"] is None:
            out["tls_ok"] = False
            out["tls_issue"] = out["tls_issue"] or "no HTTPS (HTTP only)"
    except (urllib.error.URLError, socket.timeout, TimeoutError,
            ConnectionError, OSError):
        pass

    return out


def _tls_reason(err: ssl.SSLCertVerificationError) -> str:
    msg = str(getattr(err, "verify_message", "") or err)
    low = msg.lower()
    if "expired" in low:
        return "certificate expired"
    if "hostname mismatch" in low or "doesn't match" in low or "ip address mismatch" in low:
        return "hostname mismatch"
    if "self signed" in low or "self-signed" in low:
        return "self-signed certificate"
    if "unable to get local issuer" in low or "unable to verify" in low:
        return "untrusted CA"
    return msg or "certificate verification failed"


def probe_all(hosts: list[str], timeout: float = 6.0, workers: int = 24) -> dict[str, dict]:
    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_host, h, timeout): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs):
            host = futs[fut]
            try:
                results[host] = fut.result()
            except Exception as exc:  # never let one host kill the batch
                results[host] = {"reachable": False, "http_status": 0,
                                 "http_via": "", "http_server": "",
                                 "http_final": "", "tls_ok": None,
                                 "tls_issue": f"probe error: {exc}"}
    return results
