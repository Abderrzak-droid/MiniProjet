import datetime
import time
from django.shortcuts import render , redirect
from django.http import HttpResponse
import subprocess
from .forms import ScanForm ,HomeForm , SignupForm , LoginForm# Assurez-vous d'importer les formulaires
import xml.etree.ElementTree as ET
from django.contrib import messages
from FirstTry.models import Home
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm
from django.contrib.auth import authenticate, login

# Create your views here.

def user_signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        
        form.save()
        return render(request, 'hello/Login.html')
    else:
        form = SignupForm()
    return render(request, 'hello/SignIn.html', {'form': form})


def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        
        usrname = form['username'].value()
        pssword = form['password'].value()
        user = authenticate(request, username=usrname, password=pssword)
        if user:
            login(request, user)    
            data = Home.objects.all()

            return render(request,"hello/DisplayScans.html",{'data': data})
        else:
            return HttpResponse("n'est pas valide")
 
    else:
        form = LoginForm()
        print('ca marche pas')
    return render(request, 'hello/Login.html', {'form': form})



def home(request):
    data = Home.objects.all()

    return render(request,"hello/DisplayScans.html",{'data': data})


def index(request):
    return render(request,"hello/Home.html")

def AddTask(request):
    return render(request,"hello/NewTask.html")

def runCommand(scanForm) :
    Type = scanForm['scan_type'].value()
    db = scanForm["dataBase"].value()
    IpAddress = scanForm["ip_address"].value()
    if db == "Simple Scan":
        command = "nmap -oX output.xml "+ Type +" "+ IpAddress
    else:
        command = "nmap -oX output.xml -sV --script "+db+" "+IpAddress

    try:
        subprocess.run(command, shell=True, check=True)
        return HttpResponse("Succes dans l'exécution de la commande")
    except subprocess.CalledProcessError as e:
        return HttpResponse("Erreur lors de l'exécution de la commande:", e)
    
def viewhtml (request) :
    return render(request,"hello/index.html")

#hadi hia akher 7adja ********************************************
def form(request):
    if request.method == 'POST':
        scan_form = ScanForm(request.POST)
     
        if scan_form.is_valid():
            # Sauvegarder les données du formulaire
            scan_form.save()
            your_view(request)

    else:
        scan_form = ScanForm()
   
    return render(request, "hello/NewTask.html", {'scan_form': scan_form})
    


def byScanType(request):
    scanForm = ScanForm(request.POST)
    runCommand(scanForm)
    # Chemin vers le fichier XML généré par Nmap
    xml_file_path = 'output.xml'
    
    if scanForm['scan_type'].value() == "-sT":
        # Exécutez le scan Nmap et extrayez les informations du fichier XML
        ports_info = parseNmapXmlCaseTcpPing(request,xml_file_path)
        # Passez les informations extraites au template
        return render(request, 'hello/ind.html', {'ports_info': ports_info})
    else:
        return HttpResponse("scan type n'est pas TCP Ping")

def your_view(request):

    scanForm = ScanForm(request.POST)
    
    # Sauvegarder les données du formulaire
    homeForm = HomeForm({
            'name_scan': scanForm['name'].value(),
            'status': "Done",
            'ip_address_scan':scanForm['ip_address'].value(),
    }   
    )
    homeForm.save()
    
    # Chemin vers le fichier XML généré par Nmap
    xml_file_path = 'output.xml'
            
    Data = scanForm['dataBase'].value()
    runCommand(scanForm)
    match Data:
    
        case "vuln":
            
            return HttpResponse(Data)
                    
        case "vulners":
                # Exécutez le scan Nmap et extrayez les informations du fichier XML
            ports_info = parseNmapXmlCaseVulners(request,xml_file_path)
                # Passez les informations extraites au template
            return render(request, 'hello/ShowResults.html', {'ports_info': ports_info})
        
        case "Simple Scan":
            
            ports_info = parseNmapXmlCaseTcpPing(request,xml_file_path)
            # Passez les informations extraites au template
            return render(request, 'hello/TcpPingResults.html', {'ports_info': ports_info})

    
        




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

        messages.success(request, 'Your message here')

        return extracted_table

    except Exception as e:

        messages.error(request,"Une erreur s'est produite lors de l'analyse du fichier XML : {e}")
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

        
        messages.success(request, 'Your message here')

        return ports
    
    except Exception as e:

        messages.error(request,"Une erreur s'est produite lors de l'analyse du fichier XML : {e}")
        return []   
    

    #kiyriguelha hamza nkemlouha ******************
# def AddSchedule(request):
#     data =dateasynForm(request.POST)
#     if data.is_valid():
        
#             d=0

#             duration = data['recurrence'].value()
#             if duration == "daily":
#                 d = 1
#             elif duration == "weekly":
#                 d = 7
#             elif duration == "yearly":
#                 d = 365
#             elif duration == "monthly":
#                 d = 30

#     #run_scan_view(request)
#             scan_datetime=datetime.datetime.now()
#             scan_datetime = data.cleaned_data['start_time']
    
    
#     return render(request,"hello/NewSchedule.html")
def scheduled_periodic_scan(form, scan_datetime, period_days):
    current_datetime = datetime.datetime.now(datetime.timezone.utc)
    

    if scan_datetime > current_datetime:
        time_diff = (scan_datetime - current_datetime).total_seconds()
        print("Waiting for initial scheduled scan at:", scan_datetime.strftime("%Y-%m-%d %H:%M:%S"))
        print("Time left:", datetime.timedelta(seconds=time_diff))
        print("current:", current_datetime.strftime("%Y-%m-%d %H:%M:%S"))
        # Wait until the initial scan time arrives
        time.sleep(time_diff)
        print("Initial scheduled scan started at:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        while True:
            # Run the scan command
            runCommand(form)
            print("Scan completed at:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            # Calculate next scan datetime
            scan_datetime += datetime.timedelta(days=period_days)
            # Calculate time difference until next scan
            time_diff = (scan_datetime - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
            if time_diff > 0:
                print("Next scheduled scan at:", scan_datetime.strftime("%Y-%m-%d %H:%M:%S"))
                print("Time left until next scan:", datetime.timedelta(seconds=time_diff))
                # Wait until the next scan time arrives
                time.sleep(time_diff)
            else:
                print("Error: Next scheduled scan time has already passed.")
                break
    else:
        print("Waiting for initial scheduled scan at:", scan_datetime.strftime("%Y-%m-%d %H:%M:%S"))
        print("current:", current_datetime.strftime("%Y-%m-%d %H:%M:%S"))
        print("Scheduled time has already passed.")