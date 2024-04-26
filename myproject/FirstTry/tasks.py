import subprocess
from celery import shared_task
import time
import xml.etree.ElementTree as ET
from django.http import HttpResponse

# app = Celery('tasks', broker='pyamqp://0.0.0.0:5672',
#              backend='rpc://'
#              )
# @app.task
# def waiting():
#     time.sleep(10)

def runCommand(scanForm) :
    
    Type = scanForm['scan_type']
    db = scanForm["dataBase"]
    IpAddress = scanForm["ip_address"]
    if db == "Simple Scan":
        command = "nmap -oX output.xml "+ Type +" "+ IpAddress
    else:
        command = "nmap -oX output.xml -sV --script "+db+" "+IpAddress

    try:
        subprocess.run(command, shell=True, check=True)
        return HttpResponse("Succes dans l'exécution de la commande")
    except subprocess.CalledProcessError as e:
        return HttpResponse("Erreur lors de l'exécution de la commande:", e)



@shared_task
def runTask(scan_form_data, xml_file_path):
       # Your existing scan logic goes here
    runCommand(scan_form_data)
    if 'dataBase' in scan_form_data:
        database_value = scan_form_data['dataBase']
        
        if isinstance(database_value, str):
            if database_value == "vuln":
                return "vuln"
            elif database_value == "vulners":
                ports_info = parseNmapXmlCaseVulners(xml_file_path)
                return ports_info
            elif database_value == "Simple Scan":
                ports_info = parseNmapXmlCaseTcpPing(xml_file_path)
                return ports_info
        else:
            # Handle the case when the 'dataBase' value is not a string
            return f"Invalid data type for 'dataBase': {type(database_value)}"
    else:
        # Handle the case when the 'dataBase' key is missing
        return "Missing 'dataBase' key in the dictionary"


def parseNmapXmlCaseVulners(request,xml_file):

    
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

            extracted_table.append({'id': id,
                         'cvss': cvss,
                          'type':Type,
                          'is_exploit':isExploitable
                          })

        
        return extracted_table

    except Exception as e:

        return extracted_table 
    

def parseNmapXmlCaseTcpPing(request,xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        ports = []
        for port in root.findall('.//port'):
            port_number = port.get('portid')
            state = port.find('.//state').get('state')
            service_element = port.find('.//service')

            if service_element is not None:
               service = service_element.get('name')
            else:
                service = "N/A"
            ports.append({'port': port_number,
                         'state': state,
                          'service': service,
                          })

    

        return ports
    
    except Exception as e:

        return []   

    
@shared_task
def mock():
    time.sleep(10)
@shared_task
def add(x, y):
    return x + y


@shared_task
def mul(x, y):
    return x * y


@shared_task
def xsum(numbers):
    return sum(numbers)


