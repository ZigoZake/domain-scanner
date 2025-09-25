import whois

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return dict(w)
    except Exception as e:
        return {"error": str(e)}