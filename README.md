✅ README.md
# 🔍 Domain Scanner

A modular Python tool to perform comprehensive domain reconnaissance. It gathers WHOIS info, DNS records, subdomains, open ports, detected technologies, and vulnerabilities using `nmap`, `nuclei`, and more.

---

## 🚀 Features

- WHOIS lookup
- DNS enumeration (A, AAAA, MX, NS, TXT)
- Subdomain brute-force
- Port scanning (1–1000)
- Technology detection via HTTP headers
- Vulnerability scanning using **Nuclei**

---

## 📦 Requirements

Install all dependencies using:

```bash
pip install -r requirements.txt
```
---

## 🔧 Setup
### 1.	Clone the repository:
```bash
git clone https://github.com/your-username/domain-scanner.git
cd domain-scanner
```

### 2.	Install dependencies:
```bash
pip install -r requirements.txt
```
### 3.	Make sure the following external tools are installed:
- Nmap
- Nuclei
---

## 🛠️ Usage
Run the scanner:
```bash
python scanner.py
```

Then enter a domain when prompted:
```bash
Enter domain (e.g., example.com): example.com
```
Report is saved to:
```bash
reports/example.com_report.json
```

---

## 📁 Output Format
JSON file with the following structure:
```json
{
  "domain": "example.com",
  "whois": { ... },
  "dns": { ... },
  "subdomains": [ ... ],
  "open_ports": [ ... ],
  "technologies": { ... },
  "vulnerabilities": [ ... ]
}
```
---

## 📂 Project Structure
<pre> .
├── scanner.py                # Main runner
├── reports/                  # Scan outputs
├── requirements.txt
├── README.md
├── LICENSE
└── modules/
   ├── whois_lookup.py
   ├── dns_enum.py
   ├── subdomain_enum.py
   ├── port_scan.py
   ├── tech_detect.py
   └── vuln_scan.py
 </pre>
---

## 🛡️ Disclaimer
This tool is for educational and authorized testing purposes only. Always get proper permission before scanning any domain or system.
---

## 🧑‍💻 Author
Zigo Zake <br>
GitHub: [ZigoZake](https://github.com/ZigoZake) <br>
Site: https://zigozake.com <br>

---

## ✅ `requirements.txt`

```txt
requests
python-whois
dnspython
python-nmap
You may optionally freeze with exact versions:
pip freeze > requirements.txt
```