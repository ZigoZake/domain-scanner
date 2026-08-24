# Domain Scanner

A cross-platform Python tool for domain reconnaissance. It gathers WHOIS data, DNS records, subdomains, open ports, web technology fingerprints, vulnerability scan status, and a heuristic domain reputation summary.

## Features

- WHOIS lookup
- DNS enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA)
- Common subdomain discovery
- Port scanning with nmap when available, with a socket fallback otherwise
- HTTP technology detection
- Vulnerability scan via Nuclei if installed
- JSON report generation suitable for Windows, macOS, and Linux
- Human-readable summary at the end of each scan

## Requirements

- Python 3.10+
- A virtual environment is recommended, but not required

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Optional external tools:

- Nmap, for more reliable port scanning
- Nuclei CLI, for vulnerability scanning

On macOS, install optional tools with Homebrew when needed:

```bash
brew install nmap nuclei
```

On Windows or Linux, install the same tools using your preferred package manager or official installer.

## Usage

Run the scanner with a domain argument:

```bash
python scan.py example.com
```

Or with the explicit flag:

```bash
python scan.py --domain example.com
```

Or interactively:

```bash
python scan.py
```

The script writes a JSON report to a `reports/` directory. The report file name is sanitized so it works across operating systems.

Example output path:

```text
reports/example.com_report.json
```

## Report structure

```json
{
 "domain": "example.com",
 "generated_at": "2026-08-24T12:00:00+00:00",
 "whois": { ... },
 "dns": { ... },
 "subdomains": [ ... ],
 "ports": { "status": "ok", "ports": [ ... ] },
 "technologies": { ... },
 "vulnerabilities": { ... },
 "reputation": { ... },
 "summary": { ... }
}
```

## Cross-platform notes

- Path handling uses `pathlib.Path` instead of OS-specific string paths.
- File names sanitize characters before writing to disk.
- The script does not rely on Unix-only shell commands.

## Disclaimer

This project is intended for educational and authorized testing use only. Always obtain explicit permission before scanning any domain or system.

## License

MIT