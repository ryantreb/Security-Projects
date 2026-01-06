#!/usr/bin/env python3
"""PortScan-Lite: A simple port scanner for localhost."""

import argparse
import json
import re
import socket
import urllib.parse
from datetime import datetime

try:
    from colorama import init, Fore
    init()
    GREEN = Fore.GREEN
    RED = Fore.RED
    RESET = Fore.RESET
except ImportError:
    GREEN = ""
    RED = ""
    RESET = ""


# Hardening tips for common services/ports
HARDENING_TIPS = {
    21: "Mitigation: Disable FTP if not needed, use SFTP instead, enforce strong credentials.",
    22: "Mitigation: Disable root login, enforce key-based auth, use Fail2Ban.",
    23: "Mitigation: Disable Telnet immediately, use SSH instead.",
    25: "Mitigation: Enable SMTP authentication, use TLS, configure SPF/DKIM/DMARC.",
    53: "Mitigation: Restrict zone transfers, enable DNSSEC, limit recursive queries.",
    80: "Mitigation: Enforce HTTPS redirect, configure HSTS, hide server tokens.",
    110: "Mitigation: Disable POP3 if not needed, require TLS/SSL encryption.",
    143: "Mitigation: Require TLS/SSL for IMAP, disable plaintext authentication.",
    443: "Mitigation: Use TLS 1.2+, configure strong ciphers, enable HSTS.",
    445: "Mitigation: Disable SMBv1, require signing, restrict access by IP.",
    1433: "Mitigation: Use Windows Auth, encrypt connections, restrict network access.",
    1521: "Mitigation: Enable Oracle network encryption, use strong passwords.",
    3306: "Mitigation: Bind to localhost only, require SSL, use strong passwords.",
    3389: "Mitigation: Enable NLA, use strong passwords, limit access via firewall.",
    5432: "Mitigation: Require SSL connections, use strong passwords, restrict pg_hba.conf.",
    5900: "Mitigation: Use VNC over SSH tunnel, require strong passwords.",
    6379: "Mitigation: Bind to localhost, require AUTH password, disable dangerous commands.",
    8080: "Mitigation: Apply same hardening as port 80, ensure proxy configs are secure.",
    8443: "Mitigation: Apply same hardening as port 443, verify certificate validity.",
    27017: "Mitigation: Enable authentication, bind to localhost, use TLS.",
}

DEFAULT_HARDENING_TIP = "Mitigation: Ensure service is patched and firewall rules restrict access."


def get_hardening_tip(port: int) -> str:
    """Get hardening advice for a specific port."""
    return HARDENING_TIPS.get(port, DEFAULT_HARDENING_TIP)


def check_port(ip: str, port: int, timeout: float = 1.0) -> tuple[bool, str]:
    """Check if a port is open and try to grab the service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result != 0:
                return False, ""
            # Port is open, try to grab banner
            banner = ""
            try:
                sock.settimeout(1.0)
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()
            except (socket.timeout, socket.error):
                pass
            # If no banner, try HTTP probe
            if not banner:
                try:
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    sock.settimeout(1.0)
                    data = sock.recv(1024)
                    banner = data.decode("utf-8", errors="replace").strip()
                except (socket.timeout, socket.error):
                    pass
            return True, banner
    except socket.error:
        return False, ""


def load_ports(config_file: str = "ports.json") -> list[int]:
    """Load the list of ports from the config file."""
    with open(config_file, "r") as f:
        config = json.load(f)
    return config.get("ports", [])


def extract_software_version(banner: str) -> str | None:
    """Extract software name and version from a banner string."""
    # Common patterns for software/version identification
    patterns = [
        # Server: Apache/2.4.41 or Server: nginx/1.18.0
        r'Server:\s*([A-Za-z0-9_-]+/[\d.]+)',
        # SSH-2.0-OpenSSH_8.2p1
        r'(OpenSSH[_\s][\d.p]+)',
        # Python/3.12.3
        r'(Python/[\d.]+)',
        # SimpleHTTP/0.6
        r'(SimpleHTTP/[\d.]+)',
        # Apache/2.4.41 (standalone)
        r'(Apache/[\d.]+)',
        # nginx/1.18.0 (standalone)
        r'(nginx/[\d.]+)',
        # MySQL 8.0.23
        r'(MySQL\s*[\d.]+)',
        # PostgreSQL 13.2
        r'(PostgreSQL\s*[\d.]+)',
        # Microsoft-IIS/10.0
        r'(Microsoft-IIS/[\d.]+)',
        # Generic: Word/Version pattern
        r'([A-Za-z][A-Za-z0-9_-]*/[\d]+\.[\d.]+)',
        # Generic: Word space Version
        r'([A-Za-z][A-Za-z0-9_-]+\s+[\d]+\.[\d.]+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def get_cve_search_url(banner: str) -> str | None:
    """Generate a NIST NVD search URL from a service banner."""
    if not banner:
        return None

    # Try to extract clean software/version
    software = extract_software_version(banner)
    if not software:
        return None

    # Clean up the software string for search query
    query = software.replace('_', ' ').replace('/', ' ')
    encoded_query = urllib.parse.quote_plus(query)

    # Generate NIST NVD search URL
    return f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={encoded_query}&search_type=all"


def scan_ports(ip: str, ports: list[int]) -> list[dict]:
    """Scan all ports and return results."""
    results = []
    for port in ports:
        is_open, banner = check_port(ip, port)
        results.append({"port": port, "open": is_open, "banner": banner})
        status = f"{GREEN}OPEN{RESET}" if is_open else f"{RED}CLOSED{RESET}"
        line = f"  Port {port}: {status}"
        if banner:
            line += f" | Banner: {banner[:60]}"
        print(line)
    return results


def save_results(ip: str, results: list[dict], output_file: str = "results.txt"):
    """Save scan results to a file with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, "a") as f:
        f.write(f"\n--- Scan Results for {ip} at {timestamp} ---\n")
        for result in results:
            status = "OPEN" if result["open"] else "CLOSED"
            line = f"  Port {result['port']}: {status}"
            if result.get("banner"):
                line += f" | Banner: {result['banner']}"
            f.write(line + "\n")


def save_json_log(ip: str, results: list[dict], output_file: str = "scan_log.json"):
    """Save scan results to a JSON log file."""
    timestamp = datetime.now().isoformat()
    open_ports = [
        {"port": r["port"], "service_banner": r.get("banner", "")}
        for r in results if r["open"]
    ]
    entry = {
        "target_ip": ip,
        "timestamp": timestamp,
        "open_ports": open_ports
    }
    # Load existing log or create new list
    try:
        with open(output_file, "r") as f:
            log = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log = []
    log.append(entry)
    with open(output_file, "w") as f:
        json.dump(log, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="PortScan-Lite: A simple port scanner with banner grabbing.",
        epilog="Examples:\n"
               "  python3 scanner.py                    Scan localhost with default ports\n"
               "  python3 scanner.py 192.168.1.1        Scan specific IP with default ports\n"
               "  python3 scanner.py --ports 22 80 443  Scan localhost on specific ports\n"
               "  python3 scanner.py 10.0.0.1 -p 8080   Scan specific IP and port",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "ip",
        nargs="?",
        default="127.0.0.1",
        help="Target IP address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        help="Ports to scan (default: load from ports.json)"
    )
    args = parser.parse_args()

    target_ip = args.ip
    ports = args.ports if args.ports else load_ports()

    print(f"Scanning {target_ip}...")
    results = scan_ports(target_ip, ports)
    save_results(target_ip, results)
    save_json_log(target_ip, results)

    open_count = sum(1 for r in results if r["open"])
    print(f"\nScan complete: {open_count}/{len(results)} ports open")
    print("Results saved to results.txt and scan_log.json")


if __name__ == "__main__":
    main()
