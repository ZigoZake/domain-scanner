import dns.resolver

def get_dns_records(domain):
    records = {}
    try:
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [r.to_text() for r in answers]
            except:
                records[record_type] = []
    except Exception as e:
        records['error'] = str(e)
    return records