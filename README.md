# Security_Automation_Suite

### Repository Structure:
```
Security_Automation_Suite/
├── scanners/           # Port scanner, vuln scanner, etc.
├── monitors/           # System and network monitoring
├── utilities/          # Helper tools and calculators
├── reports/            # Report generation and templates
├── config/             # Configuration templates
└── docs/               # Documentation and usage guides
```

### Automation Practices:
TBD


## Getting Started

### Prerequisites
- Windows 10/11, macOS, or Linux
- Python 3.9+ installed and on PATH (Python 3.13 is fine)
- Optional but recommended: Git


### 1) Clone the repository
If you don't already have the repo:

```bat
cd C:\GitHub
git clone https://github.com/JordanIKlein/Security_Automation_Suite.git
cd Security_Automation_Suite
```

If you already have the repo, just change into it:

```bat
cd C:\GitHub\Security_Automation_Suite
```


### 2) Create and activate a virtual environment (recommended)

```bat
python -m venv .venv
.venv\Scripts\activate
```

To deactivate later:

```bat
deactivate
```


### 3) Install dependencies

```bat
pip install -r requirements.txt
```

This installs the `click` package used by the CLI tools.

## Running the DNS Scanner

The DNS scanner lives at `scanners/dns_scanner.py`. It resolves common record types (A, AAAA, CNAME, MX, TXT, NS, SOA), can use a custom nameserver, optionally attempts zone transfer (AXFR), checks for wildcard DNS, and can output JSON.

Resolve common records:

```bat
python scanners\dns_scanner.py example.com
```

Pick specific record types and JSON output:

```bat
python scanners\dns_scanner.py example.com --types A AAAA MX TXT --json
```

Use a specific nameserver and timeout:

```bat
python scanners\dns_scanner.py example.com --nameserver 8.8.8.8 --timeout 3
```

Attempt a zone transfer (AXFR) from NS servers:

```bat
python scanners\dns_scanner.py example.com --axfr
```

Check for wildcard DNS:

```bat
python scanners\dns_scanner.py example.com --check-wildcard
```

Notes:
- AXFR attempts are best-effort and often blocked in production; if allowed, only a small sample of records is shown.
- Wildcard check probes a random subdomain and reports if it resolves (indicating wildcard DNS).
- You can combine flags, e.g., `--axfr --check-wildcard --json`.

## Running the HTTP/TLS Security Scanner

The HTTP/TLS scanner lives at `scanners/http_tls_security_scanner.py`. It probes an endpoint (HTTP or HTTPS), follows redirects, reports final headers, and for HTTPS shows TLS version, cipher, and certificate details. It also flags common missing security headers.

Run from the project root with a hostname:

```bat
python scanners\http_tls_security_scanner.py example.com
```

Run with a full URL and JSON output:

```bat
python scanners\http_tls_security_scanner.py https://example.com --json
```

Force scheme/port and adjust timeouts/redirects:

```bat
python scanners\http_tls_security_scanner.py example.com --scheme https --port 443 --timeout 5 --max-redirects 5
```

Skip TLS verification (use cautiously):

```bat
python scanners\http_tls_security_scanner.py example.com --scheme https --insecure
```

Notes:
- Target can be a hostname (e.g., `example.com`) or a full URL (e.g., `https://example.com`).
- If you pass a hostname without a scheme, HTTPS is preferred by default (unless you set `--scheme http` or use `--port 80`).
- HSTS is only applicable to HTTPS responses.

## Running the Port Scanner

The port scanner lives at `scanners/port_scanner.py` and scans a list of common ports by default, or a specific port if provided.

Run from the project root:

```bat
python scanners\port_scanner.py 8.8.8.8
```

Run a specific port (e.g., 443):

```bat
python scanners\port_scanner.py 8.8.8.8 --port 443
```

Alternatively, run it from inside the `scanners` folder:

```bat
cd scanners
python port_scanner.py 8.8.8.8
```

Notes:
- Use a valid IPv4 address (each octet 0–255). For example, `124.3.56.365` is invalid because 365 > 255 and will raise `socket.gaierror: getaddrinfo failed`.
- The scan uses TCP connect attempts; local firewalls or network ACLs may affect results.


## Troubleshooting

- Error: `socket.gaierror: [Errno 11001] getaddrinfo failed`
	- Cause: Invalid IP address or DNS resolution failure.
	- Fix: Use a valid IPv4 like `8.8.8.8` or a resolvable hostname.

- `python` not found
	- Ensure Python is installed and added to PATH, or try `py -3`.

- Dependencies not installed
	- Run `pip install -r requirements.txt` inside your activated virtual environment.


## Example Output

```text
Scanning IP: 8.8.8.8
Port 21: CLOSED
Port 22: CLOSED
...
Port 80: OPEN
Port 443: OPEN
```