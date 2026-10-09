import nmap

def scan_ports(target):
    scanner = nmap.PortScanner()
    print(f"Scanning {target}...")
    scanner.scan(target, arguments="-sV")
    
    results = []
    
    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            ports = scanner[host][protocol].keys()
            for port in ports:
                service = scanner[host][protocol][port]
                if service["state"] == "open":
                    results.append({
                        "port": port,
                        "protocol": protocol,
                        "service": service["name"],
                        "version": service["version"],
                        "state": service["state"]
                    })
    
    return results

# test it
findings = scan_ports("127.0.0.1")
for finding in findings:
    print(f"Port {finding['port']} | {finding['service']} | {finding['version']} | {finding['state']}")