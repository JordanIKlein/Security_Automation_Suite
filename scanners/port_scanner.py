import click
import socket
from typing import List


# Example of a simple port scanner using Python and Click
# python port_scanner.py IP_ADDRESS
# python port_scanner.py IP_ADDRESS --port 443

# Commonly used and important ports to scan
COMMON_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    69,   # TFTP
    80,   # HTTP
    88,   # Kerberos
    110,  # POP3
    119,  # NNTP
    135,  # MS RPC
    143,  # IMAP
    161,  # SNMP
    162,  # SNMP Trap
    389,  # LDAP
    443,  # HTTPS
    445,  # SMB
    465,  # SMTPS
    587,  # SMTP (TLS)
    993,  # IMAPS
    995,  # POP3S
    1433, # MS SQL
    1437, # PostgreSQL
    1812, # RADIUS (auth)
    3306, # MySQL
    3389, # RDP
    6514, # LDAP over SSL
    8080, # HTTP-alt
]

def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Try to connect to a specific port on an IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        return result == 0

@click.command()
@click.argument("ip")
@click.option("--port", type=int, help="Specify a single port to scan")
def main(ip: str, port: int):
    """Scan important ports on the given IP address (or a specific port if provided)."""
    ports_to_scan: List[int] = [port] if port else COMMON_PORTS
    click.echo(f"Scanning IP: {ip}")
    
    for p in ports_to_scan:
        open_status = scan_port(ip, p)
        status = "OPEN" if open_status else "CLOSED"
        click.echo(f"Port {p}: {status}")

if __name__ == "__main__":
    main()
