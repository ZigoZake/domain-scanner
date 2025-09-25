import requests

# Simple wordlist-based brute-force (customizable)
def get_subdomains(domain, wordlist=['www', 'mail', 'ftp', 'test']):
    found = []
    for sub in wordlist:
        url = f"http://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=2)
            found.append(f"{sub}.{domain}")
        except:
            pass
    return found