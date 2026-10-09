import requests
import nmap

def ask_ollama(prompt):
    response = requests.post("http://localhost:11434/api/generate",
        json={
            "model": "llama3.1:8b",
            "prompt": prompt,
            "stream": False
        },
        timeout=120
    )
    return response.json()["response"]

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

def analyze_findings(findings):
    for finding in findings:
        print(f"\n--- Analyzing Port {finding['port']} ({finding['service']}) ---")
        
        prompt = f"""You are a cybersecurity expert. Analyze this open port and provide:
1. Severity (Critical/High/Medium/Low)
2. What the risk is in plain English
3. One specific fix

Port: {finding['port']}
Service: {finding['service']}
Version: {finding['version']}
Protocol: {finding['protocol']}"""

        analysis = ask_ollama(prompt)
        print(analysis)

# run everything
findings = scan_ports("127.0.0.1")
analyze_findings(findings)