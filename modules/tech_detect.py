from __future__ import annotations

import re

import requests


HEADER_KEYS = [
    "server",
    "x-powered-by",
    "x-generator",
    "via",
    "x-frame-options",
    "content-type",
    "set-cookie",
]


TECHNOLOGY_PATTERNS = {
    "Apache": r"apache",
    "Nginx": r"nginx",
    "Cloudflare": r"cloudflare",
    "Express": r"express",
    "Node.js": r"nodejs|node.js",
    "PHP": r"php",
    "ASP.NET": r"asp.net|aspnet",
    "Django": r"django",
    "Flask": r"flask",
    "React": r"react",
    "WordPress": r"wordpress|wp-content",
    "Drupal": r"drupal",
    "Joomla": r"joomla",
    "Apache Tomcat": r"tomcat",
    "Gunicorn": r"gunicorn",
}


def detect_technologies(domain):
    tech = {"domain": domain, "technologies": [], "headers": {}}

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(url, timeout=8, verify=True, allow_redirects=True)
            headers = {key.lower(): value for key, value in response.headers.items()}
            tech["headers"] = headers

            for key in HEADER_KEYS:
                if key in headers:
                    tech["headers"][key] = headers[key]

            body = (response.text or "")
            found = set()
            for name, pattern in TECHNOLOGY_PATTERNS.items():
                if re.search(pattern, response.headers.get("server", "") + " " + body, re.I):
                    found.add(name)

            if found:
                tech["technologies"] = sorted(found)
            tech["status_code"] = response.status_code
            tech["url"] = url
            return tech
        except requests.RequestException as exc:
            tech["error"] = str(exc)
            continue

    tech["status"] = "unreachable"
    return tech