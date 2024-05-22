import xml.etree.ElementTree as ET
import requests

NVD_API_KEY = 'c42f7636-d19c-4e73-b60b-a222e8678055'

def get_vulnerability_details(cve_id):
    try:
        # NVD API endpoint for retrieving CVE details
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        timeout = 30 

        headers = {'API-Key': NVD_API_KEY}
        # Send the API request
        response = requests.get(url, headers=headers, timeout=timeout) 
        # Check if the request was successful
        response.raise_for_status() 
            # Parse the JSON response

        vulnerability_details = response.json()

            # Extract and return relevant information
        vulnerability_data = vulnerability_details["vulnerabilities"][0]["cve"]

        description = vulnerability_data["descriptions"][0]["value"]  # English description
            
        if description is not None:
            return description
        else:
            return "Echoué"

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Error: Invalid JSON response from the API: {e}")
    except (KeyError, IndexError) as e:
        print(f"Error: Unexpected JSON structure. {e}")

#print(parseNmapXmlCaseVulners("output.xml"))
print(get_vulnerability_details("CVE-2019-1010218"))