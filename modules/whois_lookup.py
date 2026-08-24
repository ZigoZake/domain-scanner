from __future__ import annotations

from datetime import date, datetime

import whois


def _serialize_value(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_serialize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _serialize_value(v) for k, v in value.items()}
    return value


def get_whois(domain):
    try:
        result = whois.whois(domain)
        data = _serialize_value(dict(result)) if result else {}
        return {
            "domain": domain,
            "status": data.get("status", []),
            "registrar": data.get("registrar"),
            "whois_server": data.get("whois_server"),
            "creation_date": data.get("creation_date"),
            "expiration_date": data.get("expiration_date"),
            "updated_date": data.get("updated_date"),
            "name_servers": data.get("name_servers", []),
            "emails": data.get("emails"),
            "country": data.get("country"),
            "raw": data,
        }
    except Exception as exc:
        return {
            "domain": domain,
            "error": str(exc),
            "status": "failed",
        }