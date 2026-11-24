"""Bounded HTTP response inspection with redirect reporting."""

import math
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_REDIRECTS = 10
SENSITIVE_RESPONSE_HEADERS = {"set-cookie", "set-cookie2"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validated_url(value: str) -> tuple[urllib.parse.SplitResult | None, str | None]:
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None, "Provide an http or https URL with a hostname"
        if parsed.username or parsed.password:
            return None, "URLs with embedded credentials are not supported"
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return None, "URL port must be between 1 and 65535"
        return parsed, None
    except ValueError:
        return None, "Malformed URL"


def inspect_http(
    url: str,
    timeout: float = 8.0,
    max_redirects: int = MAX_REDIRECTS,
) -> dict:
    """Inspect an HTTP(S) URL's status, headers, redirects, timing and TLS usage."""
    url = url.strip() if isinstance(url, str) else ""
    _parsed, error = _validated_url(url)
    if error:
        return {"status": "invalid_input", "url": url, "error": error}
    if (
        not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
        or not math.isfinite(timeout) or not 0.2 <= timeout <= 30
    ):
        return {"status": "invalid_input", "url": url, "error": "Timeout must be between 0.2 and 30 seconds"}
    if not isinstance(max_redirects, int) or isinstance(max_redirects, bool) or not 0 <= max_redirects <= MAX_REDIRECTS:
        return {"status": "invalid_input", "url": url, "error": "max_redirects must be between 0 and 10"}

    opener = urllib.request.build_opener(_NoRedirect)
    current, redirects = url, []
    started = time.perf_counter()
    for _ in range(max_redirects + 1):
        current_parsed, redirect_error = _validated_url(current)
        if redirect_error:
            return {"status": "invalid_redirect", "url": url, "final_url": current, "redirects": redirects, "error": redirect_error}
        request = urllib.request.Request(
            current,
            headers={"User-Agent": "NetGhost/0.1.0", "Range": "bytes=0-0"},
            method="GET",
        )
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            return {
                "status": "error", "url": url, "final_url": current,
                "redirects": redirects,
                "response_time_ms": round((time.perf_counter() - started) * 1000, 3),
                "error": str(exc),
            }

        location = response.headers.get("Location")
        if response.status in {301, 302, 303, 307, 308} and location:
            next_url = urllib.parse.urljoin(current, location)
            _, redirect_error = _validated_url(next_url)
            if redirect_error:
                response.close()
                return {"status": "invalid_redirect", "url": url, "final_url": current, "redirects": redirects, "error": redirect_error}
            if len(redirects) >= max_redirects:
                response.close()
                return {
                    "status": "redirect_limit", "url": url, "final_url": current,
                    "redirects": redirects,
                    "response_time_ms": round((time.perf_counter() - started) * 1000, 3),
                    "error": "Redirect limit reached",
                }
            redirects.append({"url": current, "status": response.status, "location": next_url})
            response.close()
            current = next_url
            continue

        headers = {
            name: ("[redacted]" if name.lower() in SENSITIVE_RESPONSE_HEADERS else value)
            for name, value in response.headers.items()
        }
        result = {
            "status": "success", "url": url, "final_url": current,
            "http_status": response.status, "headers": headers,
            "redirects": redirects,
            "response_time_ms": round((time.perf_counter() - started) * 1000, 3),
            "tls": current_parsed.scheme == "https",
        }
        response.close()
        return result

    return {"status": "redirect_limit", "url": url, "final_url": current, "redirects": redirects, "error": "Redirect limit reached"}


def register_tools(mcp) -> None:
    @mcp.tool
    def netghost_http_inspect(
        url: str,
        timeout: float = 8.0,
        max_redirects: int = MAX_REDIRECTS,
    ) -> dict:
        """Inspect an HTTP(S) URL's status, response headers, redirect chain, response time and final URL."""
        return inspect_http(url, timeout, max_redirects)
