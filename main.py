import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from port_scanner import scan_ports
from cve_lookup import lookup_cve
from win_auditor import run_audit

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

def analyze_port(finding):
    prompt = f"""You are a cybersecurity expert. Analyze this open port and provide:
1. Severity (Critical/High/Medium/Low)
2. Risk in plain English
3. One specific fix

Port: {finding['port']}
Service: {finding['service']}
Version: {finding['version']}
Protocol: {finding['protocol']}"""
    return ask_ollama(prompt)

def analyze_cve(cve):
    prompt = f"""You are a cybersecurity expert. Analyze this CVE and provide:
1. How serious is this in plain English
2. One specific fix

CVE ID: {cve['id']}
Score: {cve['score']}
Severity: {cve['severity']}
Description: {cve['description']}"""
    return ask_ollama(prompt)

def analyze_audit(finding):
    prompt = f"""You are a cybersecurity expert. Analyze this Windows security check and provide:
1. Severity (Critical/High/Medium/Low)
2. Risk in plain English
3. One specific fix

Check: {finding['check']}
Status: {finding['status']}
Detail: {finding['detail']}"""
    return ask_ollama(prompt)

def run_scanner(target):
    print(f"\n{'='*50}")
    print(f"  Vulnerability Scanner")
    print(f"  Target: {target}")
    print(f"{'='*50}\n")

    all_findings = []

    # Step 1 - Port Scan
    print("\n[1/3] Running Port Scanner...")
    ports = scan_ports(target)
    for port in ports:
        print(f"\n--- Port {port['port']} ({port['service']}) ---")
        analysis = analyze_port(port)
        print(analysis)

        # CVE lookup for each service
        if port['service']:
            cves = lookup_cve(port['service'], port['version'])
            for cve in cves[:2]:  # top 2 CVEs only
                print(f"\n  CVE: {cve['id']} | Score: {cve['score']} | Severity: {cve['severity']}")
                cve_analysis = analyze_cve(cve)
                print(cve_analysis)

        all_findings.append({
            "type": "port",
            "data": port,
        })

    # Step 2 - Windows Audit
    print("\n[2/3] Running Windows Audit...")
    audit_results = run_audit()
    for result in audit_results:
        if result['severity'] != "Safe":
            print(f"\n--- {result['check']} ({result['status']}) ---")
            analysis = analyze_audit(result)
            print(analysis)
        else:
            print(f"\n✅ {result['check']} — {result['detail']}")

        all_findings.append({
            "type": "audit",
            "data": result,
        })

    print(f"\n{'='*50}")
    print(f"  Scan Complete")
    print(f"  Total findings: {len(all_findings)}")
    print(f"{'='*50}\n")

# run it
run_scanner("127.0.0.1")