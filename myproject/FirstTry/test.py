import xml.etree.ElementTree as ET
from django.http import JsonResponse
import requests


def get_vulnerability_details(cve_id):
    # NVD API endpoint for retrieving CVE details
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Construct the API request URL with the CVE ID
    request_url = f"{url}?cveId={cve_id}"

    # Send the API request
    response = requests.get(request_url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the JSON response
        vulnerability_details = response.json()

        # Extract and return relevant information
        vulnerability_data = vulnerability_details["vulnerabilities"][0]["cve"]

        cve_id = vulnerability_data["id"]
        description = vulnerability_data["descriptions"][0]["value"]  # English description
        cvss_v3_1_score = vulnerability_data["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        cvss_v3_1_severity = vulnerability_data["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        cvss_v3_0_score = vulnerability_data["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]
        cvss_v3_0_severity = vulnerability_data["metrics"]["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
        cvss_v2_0_score = vulnerability_data["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
        cvss_v2_0_severity = vulnerability_data["metrics"]["cvssMetricV2"][0]["baseSeverity"]
        weakness = vulnerability_data["weaknesses"][0]["description"][0]["value"]
        affected_product = vulnerability_data["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"]
        affected_versions = vulnerability_data["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"]
        references = [ref["url"] for ref in vulnerability_data["references"]]


        data = [
        ("CVE ID", cve_id),
        ("Description", description),
        ("CVSS v3.1 Base Score", f"{cvss_v3_1_score} ({cvss_v3_1_severity})"),
        ("CVSS v3.0 Base Score", f"{cvss_v3_0_score} ({cvss_v3_0_severity})"),
        ("CVSS v2.0 Base Score", f"{cvss_v2_0_score} ({cvss_v2_0_severity})"),
        ("Weakness", weakness),
        ("Affected Product", affected_product),
        ("Affected Versions", f"Prior to {affected_versions}"),
        ("References", "\n".join(references)),
    ]
        return JsonResponse(data, safe=False)
    else:
        return JsonResponse({'error': f"{response.status_code} - {response.text}"})
    
def parseNmapXmlCaseVulners(xml_file):

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        extracted_table = []
        
        for table in root.findall('.//table'):
            
            for elem in table.findall('.//elem'):
                key = elem.get('key')  # Get the value of the 'key' attribute
                value = elem.text       # Get the text content of the element
                match key:
                    case 'cvss':
                        cvss = value
                    case 'is_exploit':
                        isExploitable = value
                    case 'id':
                        id = value
                    case 'type':
                        Type = value

            details = get_vulnerability_details(id)

            extracted_table.append({'nameVuln': id,
                         'cvss': cvss,
                          'type':Type,
                          'is_exploit':isExploitable,
                          'description': details,
                          })

        
        return extracted_table

    except Exception as e:
        print(e)
        return extracted_table 
    
#print(parseNmapXmlCaseVulners("output.xml"))
get_vulnerability_details("CVE-2022-1234")