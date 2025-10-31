r"""
DNS Scanner

Features:
- Resolve common DNS records: A, AAAA, CNAME, MX, TXT, NS, SOA
- Optional: specify resolver nameserver and timeout
- Optional: attempt zone transfer (AXFR) from authoritative NS
- Optional: check for wildcard DNS by probing a random subdomain
- Optional: simple DNSSEC presence check (DNSKEY records)
- JSON output option for automation

Usage (from project root on Windows):
  python scanners\dns_scanner.py example.com
  python scanners\dns_scanner.py example.com --types A AAAA MX TXT --json
  python scanners\dns_scanner.py example.com --nameserver 8.8.8.8 --timeout 3
  python scanners\dns_scanner.py example.com --axfr
  python scanners\dns_scanner.py example.com --check-wildcard
"""

from __future__ import annotations

import click
import random
import string
from typing import Any, Dict, List, Optional
import importlib


DEFAULT_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]


def _mod(name: str):
	"""Lazy import a module by name with a clearer error if missing."""
	try:
		return importlib.import_module(name)
	except ModuleNotFoundError as e:
		raise RuntimeError(
			"Missing dependency: dnspython. Install with 'pip install -r requirements.txt'."
		) from e


def _make_resolver(nameserver: Optional[str], timeout: float) -> Any:
	dns_resolver = _mod("dns.resolver")
	dns_flags = _mod("dns.flags")
	r = dns_resolver.Resolver(configure=True)
	r.lifetime = timeout
	r.timeout = timeout
	if nameserver:
		r.nameservers = [nameserver]
	# Request DNSSEC records if available (does not validate)
	try:
		r.use_edns(0, dns_flags.DO, 1232)
	except Exception:
		pass
	return r


def _resolve_one(resolver: Any, name: str, rtype: str) -> Dict[str, Any]:
	out: Dict[str, Any] = {"type": rtype, "answers": [], "error": None}
	try:
		resp = resolver.resolve(name, rtype, raise_on_no_answer=False)
		if resp.rrset is not None:
			if rtype.upper() == "MX":
				out["answers"] = [f"{r.preference} {r.exchange.to_text()}" for r in resp]
			elif rtype.upper() == "TXT":
				# Flatten TXT strings
				out["answers"] = ["".join(part.decode() if isinstance(part, bytes) else str(part) for part in r.strings) for r in resp]
			else:
				out["answers"] = [r.to_text() for r in resp]
	except (_mod("dns.resolver").NXDOMAIN, _mod("dns.resolver").NoNameservers, _mod("dns.resolver").NoAnswer) as e:
		out["error"] = str(e)
	except _mod("dns.exception").DNSException as e:
		out["error"] = str(e)
	except Exception as e:
		out["error"] = str(e)
	return out


def _check_dnssec_presence(resolver: Any, name: str) -> Dict[str, Any]:
	"""Best-effort DNSSEC presence check by querying DNSKEY.

	Returns: {supported: bool, error: str|None}
	"""
	info: Dict[str, Any] = {"supported": False, "error": None}
	try:
		resp = resolver.resolve(name, "DNSKEY", raise_on_no_answer=False)
		if resp.rrset is not None and len(resp) > 0:
			info["supported"] = True
	except (_mod("dns.resolver").NXDOMAIN, _mod("dns.resolver").NoAnswer, _mod("dns.resolver").NoNameservers) as e:
		info["error"] = str(e)
	except _mod("dns.exception").DNSException as e:
		info["error"] = str(e)
	except Exception as e:
		info["error"] = str(e)
	return info


def _random_label(length: int = 12) -> str:
	return "dwc-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def _check_wildcard(resolver: Any, zone_name: str) -> Dict[str, Any]:
	"""Check if a random subdomain resolves, indicating a possible wildcard DNS setup."""
	label = _random_label()
	fqdn = f"{label}.{zone_name}"
	info: Dict[str, Any] = {"random": fqdn, "resolves": False, "answers": [], "error": None}
	try:
		resp = resolver.resolve(fqdn, "A", raise_on_no_answer=False)
		if resp.rrset is not None:
			info["resolves"] = True
			info["answers"] = [r.to_text() for r in resp]
	except _mod("dns.exception").DNSException as e:
		info["error"] = str(e)
	except Exception as e:
		info["error"] = str(e)
	return info


def _attempt_axfr(zone_name: str, nameservers: List[str], timeout: float) -> Dict[str, Any]:
	"""Attempt a DNS zone transfer from each NS hostname.

	Returns mapping with details per NS. Only record minimal results to avoid huge outputs.
	"""
	results: Dict[str, Any] = {}
	for ns in nameservers:
		ns_host = ns.rstrip('.')
		entry: Dict[str, Any] = {"server": ns_host, "success": False, "error": None, "records_sample": []}
		try:
			dns_query = _mod("dns.query")
			dns_zone = _mod("dns.zone")
			xfr = dns_query.xfr(ns_host, zone_name, timeout=timeout)
			zone = dns_zone.from_xfr(xfr)
			if zone is not None:
				entry["success"] = True
				# Capture a small sample of records for report context
				for (name, ttl, rdata) in list(zone.iterate_rdatas())[:20]:
					entry["records_sample"].append({
						"name": name.to_text(),
						"ttl": ttl,
						"rdata": rdata.to_text(),
					})
		except Exception as e:
			entry["error"] = str(e)
		results[ns_host] = entry
	return results


@click.command()
@click.argument("name")
@click.option("--types", "record_types", multiple=True, type=click.Choice(DEFAULT_TYPES, case_sensitive=False), help="Record types to resolve. Default: all common types.")
@click.option("--nameserver", type=str, default=None, help="DNS server IP to use (e.g., 1.1.1.1). Defaults to system resolver.")
@click.option("--timeout", type=float, default=3.0, show_default=True, help="DNS query timeout (seconds)")
@click.option("--axfr", is_flag=True, help="Attempt DNS zone transfer from NS servers")
@click.option("--check-wildcard", is_flag=True, help="Probe a random subdomain to detect wildcard DNS")
@click.option("--dnssec", is_flag=True, help="Best-effort DNSSEC presence check (DNSKEY)")
@click.option("--json", "json_output", is_flag=True, help="Output JSON instead of text")
def main(name: str, record_types: List[str], nameserver: Optional[str], timeout: float, axfr: bool, check_wildcard: bool, dnssec: bool, json_output: bool):
	"""Resolve DNS records for NAME and perform optional checks."""
	# Normalize input and types
	qname = name.rstrip('.')
	types = [t.upper() for t in record_types] if record_types else DEFAULT_TYPES

	resolver = _make_resolver(nameserver, timeout)

	results: Dict[str, Any] = {
		"input": qname,
		"nameserver": nameserver or "system",
		"timeout": timeout,
		"records": {},
		"ns": [],
		"axfr": None,
		"wildcard": None,
		"dnssec": None,
	}

	# Resolve requested types
	for t in types:
		results["records"][t] = _resolve_one(resolver, qname, t)

	# Collect NS list for potential AXFR and reporting
	ns_result = results["records"].get("NS")
	if ns_result and ns_result.get("answers"):
		results["ns"] = ns_result["answers"]

	# Optional AXFR
	if axfr and results["ns"]:
		results["axfr"] = _attempt_axfr(qname, results["ns"], timeout)

	# Optional wildcard check
	if check_wildcard:
		results["wildcard"] = _check_wildcard(resolver, qname)

	# Optional DNSSEC presence
	if dnssec:
		results["dnssec"] = _check_dnssec_presence(resolver, qname)

	if json_output:
		import json

		click.echo(json.dumps(results, indent=2))
		return

	# Human-friendly output
	click.echo(f"DNS scan for: {qname}")
	click.echo(f"Resolver: {results['nameserver']}  Timeout: {timeout}s")

	for t in types:
		r = results["records"].get(t, {})
		if r.get("answers"):
			click.echo(f"{t}:")
			for a in r["answers"]:
				click.echo(f"  - {a}")
		elif r.get("error"):
			click.echo(f"{t}: (error) {r['error']}")
		else:
			click.echo(f"{t}: (no answer)")

	if results["ns"]:
		click.echo("\nName servers:")
		for ns in results["ns"]:
			click.echo(f"  - {ns}")

	if axfr and results.get("axfr") is not None:
		click.echo("\nAXFR attempts:")
		for server, info in results["axfr"].items():
			status = "SUCCESS" if info.get("success") else "failed"
			click.echo(f"  {server}: {status}")
			if info.get("error"):
				click.echo(f"    error: {info['error']}")
			if info.get("records_sample"):
				click.echo(f"    sample ({len(info['records_sample'])} records):")
				for rec in info["records_sample"][:5]:
					click.echo(f"      {rec['name']} {rec['ttl']} {rec['rdata']}")

	if check_wildcard and results.get("wildcard") is not None:
		wc = results["wildcard"]
		click.echo("\nWildcard check:")
		click.echo(f"  random: {wc['random']}")
		click.echo(f"  resolves: {wc['resolves']}")
		if wc.get("answers"):
			for a in wc["answers"]:
				click.echo(f"    - {a}")
		if wc.get("error"):
			click.echo(f"  error: {wc['error']}")

	if dnssec and results.get("dnssec") is not None:
		ds = results["dnssec"]
		click.echo("\nDNSSEC:")
		click.echo(f"  DNSKEY present: {ds['supported']}")
		if ds.get("error"):
			click.echo(f"  note: {ds['error']}")


if __name__ == "__main__":
	main()

