import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def lookup_cve(service, version):
    print(f"Looking up CVEs for {service} {version}...")
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    params = {
    "keywordSearch": service,
    "resultsPerPage": 5
} 
    
    try:
        response = requests.get(url, params=params, timeout=60, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            cves = []
            
            for item in data["vulnerabilities"]:
                cve = item["cve"]
                cve_id = cve["id"]
                description = cve["descriptions"][0]["value"]
                
                try:
                 if "cvssMetricV31" in cve["metrics"]:
                  score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                  severity = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                 elif "cvssMetricV2" in cve["metrics"]:
                  score = cve["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
                  severity = cve["metrics"]["cvssMetricV2"][0]["baseSeverity"]
                 else:
                  score = "N/A"
                  severity = "N/A"
                except:
                  score = "N/A"
                  severity = "N/A"
                
                cves.append({
                    "id": cve_id,
                    "description": description,
                    "score": score,
                    "severity": severity
                })
            
            return cves
        
        else:
            print(f"API returned status code: {response.status_code}")
            return []
    
    except requests.exceptions.Timeout:
        print("NVD API timed out — skipping CVE lookup")
        return []
    
    except Exception as e:
     print(f"Error type: {type(e).__name__}")
    print(f"Error details: {e}")
    return []

# test it
print("Starting CVE lookup...")
results = lookup_cve("mysql", "8.0.45")
print(f"Total CVEs found: {len(results)}")
for cve in results:
    print(f"\n{cve['id']} | Score: {cve['score']} | Severity: {cve['severity']}")
    print(f"{cve['description'][:200]}...")
print("Done.")