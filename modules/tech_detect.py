import requests

def detect_technologies(domain):
    tech = {}
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        headers = r.headers

        if 'server' in headers:
            tech['Server'] = headers['server']
        if 'x-powered-by' in headers:
            tech['X-Powered-By'] = headers['x-powered-by']
    except Exception as e:
        tech['error'] = str(e)
    return tech