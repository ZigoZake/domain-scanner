import nmap

def scan_ports(domain):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=domain, arguments='-Pn -T4 -p 1-1000')
        hosts = scanner.all_hosts()

        if not hosts:
            return {"error": f"Could not scan host: {domain}"}
        
        target = hosts[0] # Use resolved host from scan result

        open_ports = []
        for proto in scanner[target].all_protocols():
            for port in scanner[target][proto]:
                if scanner[target][proto][port]['state'] == 'open':
                    open_ports.append({
                        "port": port,
                        "protocol": proto,
                        "service": scanner[target][proto][port].get('name', '')
                    })

        return open_ports if open_ports else ["No open ports found."]
    except Exception as e:
        return {"error": str(e)}
