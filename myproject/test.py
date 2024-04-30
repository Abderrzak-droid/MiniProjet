import nmap

# Create an instance of the PortScanner class
nm = nmap.PortScanner()

# Define the scan type and options
scan_type = ' -sV --script=vulners'  # Vulnerability scan with version detection and NSE scripts
 # File containing a list of target IP addresses or hostnames

# Read the target database file and create a list of targets
target = '192.168.56.101'

# Perform the scan for each target

scan_result = nm.scan(hosts=target, arguments=scan_type)
print(f"Scan results for {target}:")
print(scan_result['scan'][target]['hostscript'])

# Access the vulnerability details from the scan results
for host, scan_data in scan_result['scan'].items():
    if 'hostscript' in scan_data:
        nm.get_nmap_last_output()