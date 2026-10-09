import subprocess

def check_smb():
    print("Checking SMBv1...")
    result = subprocess.run(
        ["powershell", "-Command", "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"],
        capture_output=True,
        text=True
    )
    if "Enabled" in result.stdout:
        return {
            "check": "SMBv1",
            "status": "ENABLED",
            "severity": "Critical",
            "detail": "SMBv1 is enabled — vulnerable to EternalBlue/WannaCry"
        }
    else:
        return {
            "check": "SMBv1",
            "status": "DISABLED",
            "severity": "Safe",
            "detail": "SMBv1 is disabled — good"
        }

def check_rdp():
    print("Checking RDP...")
    result = subprocess.run(
        ["powershell", "-Command", 
         "Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections"],
        capture_output=True,
        text=True
    )
    if "0" in result.stdout:
        return {
            "check": "RDP",
            "status": "ENABLED",
            "severity": "High",
            "detail": "RDP is enabled — remote access is open"
        }
    else:
        return {
            "check": "RDP",
            "status": "DISABLED",
            "severity": "Safe",
            "detail": "RDP is disabled — good"
        }

def check_firewall():
    print("Checking Firewall...")
    result = subprocess.run(
        ["powershell", "-Command", "Get-NetFirewallProfile | Select-Object Name, Enabled"],
        capture_output=True,
        text=True
    )
    if "False" in result.stdout:
        return {
            "check": "Firewall",
            "status": "PARTIALLY DISABLED",
            "severity": "High",
            "detail": "One or more firewall profiles are disabled"
        }
    else:
        return {
            "check": "Firewall",
            "status": "ENABLED",
            "severity": "Safe",
            "detail": "All firewall profiles are enabled — good"
        }

def run_audit():
    print("\n--- Running Windows Security Audit ---\n")
    results = []
    results.append(check_smb())
    results.append(check_rdp())
    results.append(check_firewall())
    return results

# test it
findings = run_audit()
for finding in findings:
    print(f"\nCheck: {finding['check']}")
    print(f"Status: {finding['status']}")
    print(f"Severity: {finding['severity']}")
    print(f"Detail: {finding['detail']}")