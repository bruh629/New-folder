import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("Sending request...")

try:
    response = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": "mysql", "resultsPerPage": 1},
        timeout=30,
        verify=False
    )
    print(f"Status code: {response.status_code}")
    print(response.text[:200])

except requests.exceptions.Timeout:
    print("Request timed out")

except requests.exceptions.ConnectionError as e:
    print(f"Connection error: {e}")

except Exception as e:
    print(f"Error: {e}")