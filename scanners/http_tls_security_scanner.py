r"""
HTTP/TLS Security Scanner

Features:
- Probe HTTP/HTTPS endpoint with HEAD request
- Follow redirects (configurable)
- Collect final response headers and basic metadata
- For HTTPS: capture TLS version, cipher, and certificate details (issuer, subject, SANs, expiry)
- Security header checks (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- JSON output option for automation

Usage examples (from project root on Windows):
  python scanners\http_tls_security_scanner.py example.com
  python scanners\http_tls_security_scanner.py https://example.com --json
  python scanners\http_tls_security_scanner.py example.com --scheme https --port 443 --timeout 5 --max-redirects 5
  python scanners\http_tls_security_scanner.py example.com --scheme https --insecure  # do not verify TLS cert

Dependencies: stdlib + click
"""

from __future__ import annotations

import click
import ssl
import socket
import http.client
from urllib.parse import urlparse, urlunparse, urljoin
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone
import json


REDIRECT_STATUSES = {301, 302, 303, 307, 308}
SECURITY_HEADERS = [
	"strict-transport-security",  # HTTPS only
	"content-security-policy",
	"x-content-type-options",
	"x-frame-options",
	"referrer-policy",
	"permissions-policy",
]


def _default_scheme(port: Optional[int]) -> str:
	if port == 80:
		return "http"
	if port == 443:
		return "https"
	# Prefer HTTPS by default
	return "https"


def _normalize_target(target: str, scheme_pref: str, port: Optional[int]) -> Tuple[str, str, int, str]:
	"""Return (scheme, host, port, path) for the initial request.

	Accepts either a hostname or a full URL.
	"""
	parsed = urlparse(target)
	if parsed.scheme in ("http", "https") and parsed.netloc:
		scheme = parsed.scheme
		host = parsed.hostname or target
		used_port = parsed.port or (443 if scheme == "https" else 80)
		path = parsed.path or "/"
		if parsed.query:
			path = f"{path}?{parsed.query}"
		return scheme, host, used_port, path

	# Not a URL, treat as hostname and build from preferences
	scheme = (
		_default_scheme(port) if scheme_pref == "auto" else scheme_pref
	)
	host = target
	used_port = port or (443 if scheme == "https" else 80)
	path = "/"
	return scheme, host, used_port, path


def _headers_to_cidict(headers: Any) -> Dict[str, str]:
	"""Convert headers to a case-insensitive dict (lowercased keys)."""
	result: Dict[str, str] = {}
	# http.client.HTTPMessage is iterable over header keys
	for k, v in headers.items():
		result[k.lower()] = v
	return result


def _build_context(insecure: bool) -> ssl.SSLContext:
	if insecure:
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		return ctx
	return ssl.create_default_context()


def _parse_cert_dates(cert: Dict[str, Any]) -> Tuple[Optional[datetime], Optional[datetime]]:
	def parse_dt(s: str) -> Optional[datetime]:
		try:
			# Example: 'Oct 30 12:00:00 2025 GMT'
			return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
		except Exception:
			return None

	not_before = parse_dt(cert.get("notBefore", "")) if cert else None
	not_after = parse_dt(cert.get("notAfter", "")) if cert else None
	return not_before, not_after


def _format_name(name_seq: Any) -> str:
	"""Format subject/issuer tuples from getpeercert into a readable string."""
	try:
		parts = []
		for rdn in name_seq:
			for k, v in rdn:
				parts.append(f"{k}={v}")
		return ", ".join(parts)
	except Exception:
		return ""


def _tls_info_from_conn(conn: http.client.HTTPSConnection) -> Dict[str, Any]:
	info: Dict[str, Any] = {}
	try:
		sock = getattr(conn, "sock", None)
		if sock and isinstance(sock, ssl.SSLSocket):
			info["tls_version"] = sock.version()
			cipher = sock.cipher()
			if cipher:
				info["cipher"] = cipher[0]
			cert = sock.getpeercert() or {}
			not_before, not_after = _parse_cert_dates(cert)
			san_dns = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
			info.update(
				{
					"cert_subject": _format_name(cert.get("subject", [])),
					"cert_issuer": _format_name(cert.get("issuer", [])),
					"cert_san_dns": san_dns,
					"cert_not_before": not_before.isoformat() if not_before else None,
					"cert_not_after": not_after.isoformat() if not_after else None,
				}
			)
			if not_after:
				delta = not_after - datetime.now(timezone.utc)
				info["cert_days_to_expire"] = max(delta.days, 0)
	except Exception as e:
		info["tls_info_error"] = str(e)
	return info


def _fetch_once(
	scheme: str,
	host: str,
	port: int,
	path: str,
	timeout: float,
	insecure: bool,
) -> Dict[str, Any]:
	"""Execute a single HEAD request and return response metadata.

	Returns dict with keys: url, scheme, host, port, status, reason, headers, ip, tls (if https), error
	"""
	url = urlunparse((scheme, f"{host}:{port}", path, "", "", ""))
	result: Dict[str, Any] = {
		"url": url,
		"scheme": scheme,
		"host": host,
		"port": port,
		"path": path,
		"status": None,
		"reason": None,
		"headers": {},
		"ip": None,
		"tls": None,
		"error": None,
	}
	try:
		# Resolve IP (best-effort)
		try:
			result["ip"] = socket.gethostbyname(host)
		except Exception:
			pass

		if scheme == "https":
			ctx = _build_context(insecure)
			conn_https = http.client.HTTPSConnection(host=host, port=port, timeout=timeout, context=ctx)
			conn_https.request("HEAD", path, headers={"User-Agent": "SAS-HTTP-TLS-Scanner/1.0"})
			resp = conn_https.getresponse()
			result["status"] = resp.status
			result["reason"] = resp.reason
			cidict = _headers_to_cidict(resp.headers)
			result["headers"] = cidict
			result["tls"] = _tls_info_from_conn(conn_https)
			conn_https.close()
		else:
			conn_http = http.client.HTTPConnection(host=host, port=port, timeout=timeout)
			conn_http.request("HEAD", path, headers={"User-Agent": "SAS-HTTP-TLS-Scanner/1.0"})
			resp = conn_http.getresponse()
			result["status"] = resp.status
			result["reason"] = resp.reason
			cidict = _headers_to_cidict(resp.headers)
			result["headers"] = cidict
			conn_http.close()
	except Exception as e:
		result["error"] = str(e)
	return result


def _follow_redirects(
	scheme: str,
	host: str,
	port: int,
	path: str,
	timeout: float,
	insecure: bool,
	max_redirects: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
	history: List[Dict[str, Any]] = []
	current = (scheme, host, port, path)
	for _ in range(max_redirects + 1):
		s, h, p, pa = current
		hop = _fetch_once(s, h, p, pa, timeout, insecure)
		history.append(hop)
		status = hop.get("status")
		if status in REDIRECT_STATUSES:
			location = hop["headers"].get("location")
			if not location:
				break
			next_url = urljoin(hop["url"], location)
			parsed = urlparse(next_url)
			ns = parsed.scheme or s
			nh = parsed.hostname or h
			np = parsed.port or (443 if ns == "https" else 80)
			npa = parsed.path or "/"
			if parsed.query:
				npa = f"{npa}?{parsed.query}"
			current = (ns, nh, np, npa)
			continue
		# Not a redirect or missing status -> stop
		break
	return history, history[-1]


def _security_header_issues(headers: Dict[str, str], is_https: bool) -> List[str]:
	issues: List[str] = []
	# HSTS only meaningful on HTTPS
	if is_https and "strict-transport-security" not in headers:
		issues.append("Missing Strict-Transport-Security (HSTS)")

	if "content-security-policy" not in headers:
		issues.append("Missing Content-Security-Policy (CSP)")

	xcto = headers.get("x-content-type-options")
	if xcto is None or xcto.lower() != "nosniff":
		issues.append("Missing or incorrect X-Content-Type-Options (expect 'nosniff')")

	if "x-frame-options" not in headers:
		issues.append("Missing X-Frame-Options")

	if "referrer-policy" not in headers:
		issues.append("Missing Referrer-Policy")

	if "permissions-policy" not in headers:
		issues.append("Missing Permissions-Policy")

	return issues


def _tls_issues(tls: Optional[Dict[str, Any]]) -> List[str]:
	issues: List[str] = []
	if not tls:
		return issues
	if tls.get("cert_days_to_expire") is not None and tls["cert_days_to_expire"] <= 14:
		issues.append("TLS certificate expires within 14 days")
	if not tls.get("tls_version"):
		issues.append("Could not determine TLS version")
	return issues


@click.command()
@click.argument("target")
@click.option("--port", type=int, default=None, help="Port to connect to (default based on scheme or 443 for auto)")
@click.option("--scheme", type=click.Choice(["auto", "http", "https"]), default="auto", show_default=True, help="Connection scheme preference for host targets")
@click.option("--timeout", type=float, default=3.0, show_default=True, help="Socket timeout (seconds)")
@click.option("--max-redirects", type=int, default=5, show_default=True, help="Maximum number of redirects to follow")
@click.option("--json", "json_output", is_flag=True, help="Output JSON instead of text")
@click.option("--insecure", is_flag=True, help="Do not verify TLS certificates (HTTPS)")
def main(target: str, port: Optional[int], scheme: str, timeout: float, max_redirects: int, json_output: bool, insecure: bool):
	"""Scan an HTTP/HTTPS endpoint for TLS info and security headers.

	TARGET may be a hostname (e.g., example.com) or a URL (e.g., https://example.com).
	"""
	scheme0, host0, port0, path0 = _normalize_target(target, scheme, port)

	# Follow redirects and collect history
	history, final_hop = _follow_redirects(
		scheme0, host0, port0, path0, timeout=timeout, insecure=insecure, max_redirects=max_redirects
	)

	final_headers = final_hop.get("headers", {}) or {}
	final_scheme = final_hop.get("scheme")
	final_tls = final_hop.get("tls") if final_scheme == "https" else None

	issues: List[str] = []
	# Connectivity / error checks
	if final_hop.get("error"):
		issues.append(f"Connection error: {final_hop['error']}")

	# Header checks
	issues.extend(_security_header_issues(final_headers, is_https=(final_scheme == "https")))

	# TLS checks
	issues.extend(_tls_issues(final_tls))

	output: Dict[str, Any] = {
		"input": target,
		"initial": {
			"scheme": scheme0,
			"host": host0,
			"port": port0,
			"path": path0,
		},
		"history": history,
		"final": final_hop,
		"issues": issues,
	}

	if json_output:
		click.echo(json.dumps(output, indent=2, default=str))
		return

	# Human-friendly text output
	click.echo(f"Scanning: {history[0]['url'] if history else target}")
	if len(history) > 1:
		click.echo("Redirect chain:")
		for i, hop in enumerate(history[:-1], 1):
			st = hop.get("status")
			loc = hop.get("headers", {}).get("location") or "(no Location)"
			click.echo(f"  {i}. {hop['url']} -> [{st}] {loc}")

	click.echo(f"Final: {final_hop.get('url')} [{final_hop.get('status')} {final_hop.get('reason')}]")

	if final_scheme == "https" and final_tls:
		click.echo("TLS:")
		click.echo(f"  Version: {final_tls.get('tls_version')}")
		click.echo(f"  Cipher: {final_tls.get('cipher')}")
		click.echo(f"  Subject: {final_tls.get('cert_subject')}")
		click.echo(f"  Issuer: {final_tls.get('cert_issuer')}")
		if final_tls.get("cert_not_after"):
			click.echo(
				f"  Expires: {final_tls.get('cert_not_after')} (in {final_tls.get('cert_days_to_expire')} days)"
			)
		if final_tls.get("cert_san_dns"):
			click.echo(f"  SANs: {', '.join(final_tls.get('cert_san_dns')[:8])}{'…' if len(final_tls.get('cert_san_dns'))>8 else ''}")

	if issues:
		click.echo("Issues:")
		for i in issues:
			click.echo(f"  - {i}")
	else:
		click.echo("Issues: none detected")


if __name__ == "__main__":
	main()

