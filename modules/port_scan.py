from __future__ import annotations

import shutil
import socket

try:
    import nmap
except ImportError:  # pragma: no cover - optional dependency
    nmap = None


def _scan_with_socket(hostname: str, port_range) -> list[dict]:
    results = []
    for port in port_range:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                sock.connect((hostname, port))
            results.append({
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": "unknown",
            })
        except OSError:
            continue
    return results


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 3306, 5432, 6379, 8080, 8081, 8443, 8888, 9000]


def scan_ports(domain, port_range=None):
    ports_to_scan = port_range or COMMON_PORTS

    if nmap is not None and shutil.which("nmap"):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=domain, arguments="-Pn -T4 -p 1-1000")
            hosts = scanner.all_hosts()
            if not hosts:
                return {"status": "failed", "error": f"Could not scan host: {domain}"}

            target = hosts[0]
            results = []
            for proto in scanner[target].all_protocols():
                for port in scanner[target][proto]:
                    if scanner[target][proto][port].get("state") == "open":
                        results.append({
                            "port": int(port),
                            "protocol": proto,
                            "state": "open",
                            "service": scanner[target][proto][port].get("name", "unknown"),
                        })
            return {"status": "ok", "ports": sorted(results, key=lambda item: item["port"]) }
        except Exception as exc:
            return {"status": "failed", "error": str(exc), "fallback": "socket"}

    try:
        host_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        try:
            host_ip = socket.gethostbyname_ex(domain)[2][0]
        except Exception:
            return {"status": "failed", "error": f"Could not resolve {domain}"}

    results = _scan_with_socket(host_ip, ports_to_scan)
    return {"status": "ok", "ports": sorted(results, key=lambda item: item["port"]) }
