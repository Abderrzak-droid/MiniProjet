import datetime
from io import BytesIO
from itertools import count
import time
from celery import Celery, shared_task
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
import subprocess
from django.urls import reverse
from .forms import CustomScanForm, ResultatsForm, ScheduleForm,ScanForm ,HomeForm , SignupForm , LoginForm , ResultatVulnersForm,ResultatTCPForm, TargetForm, TaskForm   # Assurez-vous d'importer les formulaires
import xml.etree.ElementTree as ET
from FirstTry.models import CustomScriptType, NmapScriptType, ResultVulners,Scan,Home, ResultatTCP,Schedule, Target
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth import authenticate, login
from celery.result import AsyncResult
import requests
from django.utils import timezone
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
# Create your views here.


app = Celery('myproject', backend='redis://localhost')


nmap_scan_types = {
    "TCP Connect": "-sT",
    "SYN": "-sS",
    "UDP": "-sU",
    "TCP ACK": "-sA",
    "Window": "-sW",
    "Maimon": "-sM",
    "FIN": "-sF",
    "Xmas": "-sX",
    "Null": "-sN",
    "IP Protocol": "-sO",
    "Ping": "-sn",
    "SCTP INIT": "-sY",
    "SCTP COOKIE-ECHO": "-sZ",
    "List": "-sL",
    "Idle": "-sI",
    "TCP Ping": "-PS",
    "UDP Ping": "-PU",
    "SCTP Ping": "-PY",
}
    
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

            return render(request,"hello/index.html")
        else:
            return HttpResponse("n'est pas valide")
 
    else:
        form = LoginForm()
        print('ca marche pas')
    return render(request, 'hello/Login.html', {'form': form})

def Index(request):
    return render(request,"hello/index.html")


def dashboard(request):
    data = Home.objects.all()
    return render(request,"hello/dashboard.html", {'data':data})

def home(request):
    data = Home.objects.all()

    #i want to fix the description using dictionnary.
    return render(request,"hello/DisplayScans.html",{'data': data})


def AddTask(request):
    schedule = Schedule.objects.all()
    targets = Target.objects.all()
    scans = Scan.objects.all()
    context = {'choices': schedule, 'targets':targets ,'scans' :scans}
    return render(request,"hello/NewTask.html",context)

def AddTarget(request):
    if request.method == 'POST':
        form = TargetForm(request.POST)
        if form.is_valid():
            form.save()
        else:
            return HttpResponse("form n'est pas valid")
        previous_page = request.META.get('HTTP_REFERER')
        if previous_page:
            return HttpResponseRedirect(previous_page)
        else:
        # Handle the case when there's no referrer
            return HttpResponse("No referrer found.")
    else:
        form = TargetForm()

    return render(request , 'hello/NewTarget.html',{'form': form})

def AddScan(request):
    scripts = NmapScriptType.objects.all()
    custom_scripts = CustomScriptType.objects.all()
    data = CustomScriptType.objects.all()
    print(data)
    if request.method == 'POST':
        form = ScanForm(request.POST)
        
        if not form.is_valid():
            print(form.errors)  # This will print a dictionary of errors
        # Iterate through errors and display user-friendly messages
            for field, error_list in form.errors.items():
                for error in error_list:
                    print(f"Error in field '{field}': {error}")
            return HttpResponse("form n'est pas valid")
        else:
            form.save()
            return redirect(reverse('NewTask'))
    else:
        form = ScanForm()

    return render(request , 'hello/NewScanConf.html',{'form': form , 'nmap_script_types':scripts, 'custom_scripts':custom_scripts})

def AddCustomScan(request):
    scripts = NmapScriptType.objects.all()
    
    if request.method == 'POST':
        form = CustomScanForm(request.POST)
        if not form.is_valid():
            print(form.errors)  # This will print a dictionary of errors
        # Iterate through errors and display user-friendly messages
            for field, error_list in form.errors.items():
                for error in error_list:
                    print(f"Error in field '{field}': {error}")
            return HttpResponse("form n'est pas valid")
        else:
            form.save()
            return redirect(reverse('NewScanConf'))
         
    else:
        form = CustomScanForm()

    return render(request , 'hello/NewCustomScanConf.html',{'form': form , 'nmap_script_types':scripts})

@shared_task
def runCommand(scanForm) :
    
    scan_id = scanForm['Configuration'].value()
    scan_instance = Scan.objects.get(pk = scan_id)

    scan_type = scan_instance.Scan_Name

                
    target_id = scanForm['target'].value()
    target_instance = Target.objects.get(pk = target_id)

    IpAddress = target_instance.Address_IP
    Type = nmap_scan_types["TCP Ping"]

    if scan_type != "Vulners":
        command = "nmap -oX output.xml "+ Type +" "+ IpAddress
    else:
        command = "nmap -oX output.xml -sV --script "+scan_type+" "+IpAddress

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
    

def ShowResultsTCP(request):
    return render(request, "hello/TcpPingResults.html")


def byScanType(request):
    scanForm = ScanForm(request.POST)
    runCommand(scanForm)
    # Chemin vers le fichier XML généré par Nmap
    xml_file_path = 'output.xml'
    
    if scanForm['scan_type'].value() == "-sT":
        # Exécutez le scan Nmap et extrayez les informations du fichier XML
        ports_info = parseNmapXmlCaseTcpPing(xml_file_path)
        # Passez les informations extraites au template
        return render(request, 'hello/ind.html', {'ports_info': ports_info})
    else:
        return HttpResponse("scan type n'est pas TCP Ping")

def create_task(request):
    if request.method == 'POST':
        form = TaskForm(request.POST)
        if form.is_valid():
            # Save the form data to the database
            task = form.save()
            # Redirect to a success page or another URL
            return HttpResponse('success_url')  # Replace 'success_url' with the appropriate URL
    else:
        # If it's not a POST request, create a blank form
        form = TaskForm()
    return render(request, 'hello/test.html', {'form': form})
from datetime import date, datetime, timedelta, timezone

def your_view(request):

    scanForm = TaskForm(request.POST)
    if scanForm['schedule'].value()!='Now':

        submission_time = datetime.now(timezone.utc)
        schedule_id = scanForm['schedule'].value()
        date = Schedule.objects.get(pk = schedule_id)
        schedule_name = date.Schedule_Name

    if scanForm.is_valid():
        instance = scanForm.save(commit=False)

        configuration_id = scanForm['Configuration'].value()
        scan_configuration_instance = Scan.objects.get(pk = configuration_id)

        target_id = scanForm['target'].value()
        target_instance = Target.objects.get(pk = target_id)


        print("'name':", scanForm['name'].value(),
                "'target':", target_instance.Address_IP,
                "'Configuration': ",scan_configuration_instance.Scan_Name,
                "'status': In progress ...",
                "'schedule': ",date.Schedule_Name,
                "'Creation_time': ",submission_time)
        
        # Sauvegarder les données du formulaire
        homeForm = HomeForm({
                'name': scanForm['name'].value(),
                'target': target_instance.Address_IP,
                'Configuration': scan_configuration_instance.Scan_Name,
                'status': "In progress ...",
                'schedule': date.Schedule_Name,
                'Creation_Time': submission_time,
        }   
        )
        if not homeForm.is_valid():
            print(homeForm.errors)  # This will print a dictionary of errors
        # Iterate through errors and display user-friendly messages
            for field, error_list in homeForm.errors.items():
                for error in error_list:
                    print(f"Error in field '{field}': {error}")
        else:
            homeForm.save()

        d=0
        recurrence = date.recurrence 

        if recurrence == "daily":
            d = 1
        elif recurrence == "weekly":
            d = 7
        elif recurrence == "yearly":
            d = 365
        elif recurrence == "monthly":
            d = 30
        elif recurrence == "none":
            d=0

        task_data_serializable = {
                'name': scanForm['name'].value(),
                'target': target_instance.Address_IP,  
                'Configuration': scan_configuration_instance.Scan_Name, 
                'schedule': schedule_id,  
                'recurrence': date.recurrence,
                'rununtil':date.run_until,
            }
        
        scan_datetime = date.start_time
        current_datetime = datetime.now(timezone.utc)

        current_minutes = current_datetime.minute

        if scan_datetime:
            minutes = scan_datetime.minute
        else:
            print("minutes est faux")
            # must be revised
            minutes = current_minutes

        time_diff = (scan_datetime - current_datetime).total_seconds()

        print("Waiting for initial scheduled scan at:", scan_datetime.strftime("%Y-%m-%d %H:%M:%S"))
        print("Time left:", timedelta(seconds=time_diff))

        target=target_instance.Address_IP

        print("target is : ",target)
        print("current:", current_datetime.strftime("%Y-%m-%d %H:%M:%S"))

        if 'checkbox' in request.POST:
            ports_info_result1 = scheduled_periodic_scan.apply_async(args=(task_data_serializable,))
        if scan_datetime >= current_datetime:
                
                #periodic_scan(task_data_serializable)
            ports_info_result = scheduled_periodic_scan.apply_async(args=(task_data_serializable,), countdown=time_diff)

        else:
            return HttpResponse("probleme du temps.")
        
        data = Home.objects.all()
        return render(request,'hello/dashboard.html',{'data': data}) # Redirect to status polling view
    else:   
        print(scanForm.errors)
        return HttpResponse("scan n'est pas valide")
# views.py
from django.http import JsonResponse
def AddSchedule(request):
    if request.method == 'POST':
        form = ScheduleForm(request.POST)
        if not form.is_valid():
            print(form.errors)  # This will print a dictionary of errors
        # Iterate through errors and display user-friendly messages
            for field, error_list in form.errors.items():
                for error in error_list:
                    print(f"Error in field '{field}': {error}")
        else:
            form.save()
            previous_page = request.META.get('HTTP_REFERER')
            if previous_page:
                return HttpResponseRedirect(previous_page)
            else:
            # Handle the case when there's no referrer
                return HttpResponse("No referrer found.")
    else:
        form = ScheduleForm()

    return render(request , 'hello/NewSchedule.html',{'form': form})


def get_vulnerability_details(cve_id):
    try:
        # NVD API endpoint for retrieving CVE details
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        timeout = 30 

        headers = {'API-Key': settings.NVD_API_KEY}
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
def ShowResults(request):
    Results = ResultVulners.objects.all()

    return render(request , "hello/ShowResults.html",{'ports_info':Results})

def check_cve_prefix(cve_id):
    return cve_id.startswith("CVE")

def parseNmapXmlCaseVulners(xml_file):

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        extracted_table = []
        id = " "
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
            print("cve is : ",id)
            if check_cve_prefix(id): 
                print("entered the cve part")
                details = get_vulnerability_details(id)
                if details is None:
                    details = " Pas de description "
                print("description de vulnerability ",id ," :" ,details)
            else : 
                details = "N'est pas identifiant de CVE"
            extracted_table.append({'nameVuln': id,
                         'cvss': cvss,
                          'type':Type,
                          'is_exploit':isExploitable,
                          'details': details,
                          })

        
        return extracted_table

    except Exception as e:

        return extracted_table 
    
@shared_task
def parseNmapXmlCaseTcpPing(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        ports = []
        for port in root.findall('.//port'):

            port_number = port.get('portid')
            state_element = port.find('.//state')
            if state_element is not None:
                state = state_element.get('state')
            else:
                state = "N/A"
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
        print(e)
        return []   
       


@shared_task
def scheduled_periodic_scan(scanForm):
    
        print("Initial scheduled scan started at:", datetime.now())
        recurrence = scanForm.get("recurrence")
        scan_type = scanForm.get("Configuration")
        print("le type est :",scan_type)

                
        IpAddress = scanForm.get("target")
        print("adresse ip est :",IpAddress)

        Type = nmap_scan_types["TCP Ping"]
        print("Type de ping est :",Type)

        if scan_type == "TCP Ping":
            command = f"nmap -oX output.xml {Type} {IpAddress}"
        else:
            command = f"nmap -oX output.xml -sV --script {scan_type} {IpAddress}"

        try:
            subprocess.run(command, shell=True, check=True)
            
        except subprocess.CalledProcessError as e:
            print(e)
            
        xml_file_path = 'output.xml'
        ports_info=[{'nothing' : 'rien a été ajouté'},]
        match scan_type:
    
            case "vuln":
                
                return HttpResponse(scan_type)
                        
            case "vulners":
                    
                ports_info = parseNmapXmlCaseVulners(xml_file_path)
                resultats = ResultatVulnersForm()
                for result in ports_info:
                    resultats = ResultatVulnersForm({
                            'vulnerability': result.get('nameVuln', 'N/A'),
                            'severity': result.get('cvss', 0.0),
                            'type': result.get('type', 'N/A'),
                            'is_exploit': result.get('is_exploit', False),
                            'description': result.get('details', "Pas de description"),
                    })
                    if not resultats.is_valid():
                        print(resultats.errors)  # This will print a dictionary of errors
            # Iterate through errors and display user-friendly messages
                        for field, error_list in resultats.errors.items():
                            for error in error_list:
                                print(f"Error in field '{field}': {error}")
                    else:
                        resultats.save()

                
            case "TCP Ping":

                ports_info = parseNmapXmlCaseTcpPing(xml_file_path)
                resultats = ResultatTCPForm()
                for result in ports_info:
                    
                    vulnerability = ResultatTCPForm({
                        'port' : result['port'],
                        'state' : result['state'],
                        'service' : result['service'],
                    }
                    )

                    vulnerability.save()
        download_report( 'pdf', scan_type, ports_info)
        # Conversion de date en datetime
        if recurrence != "one" and  scanForm.get("rununtil") >= date.today() :
            periodique(recurrence , scanForm)

        return ports_info

def periodique(val , scanForm) :
    if val == "daily":
            d = 1
    elif val == "weekly":
            d = 7
    elif val == "yearly":
            d = 365
    elif val == "monthly":
            d = 30
    elif val == "hourly" :
            # Définir la durée en heures
            h = 1  # par exemple, 48 heures

# Convertir les heures en jours
            d = h / 24
            
    #pour la fonction périodique.
    time_diff_period = (timedelta(days=d)).total_seconds()
    print ("le prochaine scan sera apres ", time_diff_period)
    scheduled_periodic_scan.apply_async(args=(scanForm,), countdown=time_diff_period)

def generate_pdf_report(scan_type, ports_info):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.setFont("Helvetica", 12)

    c.drawString(100, 750, f"Scan Report - {scan_type}")
    c.drawString(100, 735, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y = 700
    
    for info in ports_info:
        for key, value in info.items():
            c.drawString(100, y, f"{key}: {value}")
            y -= 15
            if y < 50:
                c.showPage()
                c.setFont("Helvetica", 12)
                y = 750

    c.save()
    pdf = buffer.getvalue()
    buffer.close()
    return pdf

def download_report(format, scan_type, ports_info):
    if format == 'pdf':
        pdf = generate_pdf_report(scan_type, ports_info)
        response = HttpResponse(pdf, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="scan_report_{scan_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
        return response
    elif format == 'xml':
        response = HttpResponse(content_type='application/xml')
        response['Content-Disposition'] = f'attachment; filename="scan_report_{scan_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xml"'
        xml_content = '<report>'
        for info in ports_info:
            xml_content += '<port_info>'
            for key, value in info.items():
                xml_content += f'<{key}>{value}</{key}>'
            xml_content += '</port_info>'
        xml_content += '</report>'
        response.write(xml_content)
        return response
    else:
        return HttpResponse("Unsupported format", status=400)


def ShowScans(request):
    Scans = Scan.objects.all()

    return render(request, "hello/ShowScans.html", {'scans' : Scans})

def addScan(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            form.save()
            Scans = Scan.objects.all()
            return render(request, "hello/ShowScans.html", {'scans' : Scans})
        else:
            return HttpResponse("Scan n'est pas ajouté")


def delete_row(request, row_id):
    row = get_object_or_404(Scan, id=row_id)
    if request.method == 'POST':
        row.delete()
        Scans = Scan.objects.all()
        return render(request, "hello/ShowScans.html", {'scans' : Scans})
    else:
        return HttpResponse("Scan n'est pas supprimé")
    
def vulnerability_data(request):
    data = {
        'low': ResultVulners.objects.filter(severity__lt=3).count(),
        'medium': ResultVulners.objects.filter(severity__gte=3, severity__lt=8).count(),
        'high': ResultVulners.objects.filter(severity__gte=8).count()
    }

    return JsonResponse(data)


def edit_rowScan(request):
    Scans = Scan.objects.all()
    if request.method == 'POST':
        form = ScanForm(request.POST)
        try:
            print("enter 1")
            row = Scan.objects.get(Scan_Name=form["Scan_Name"].value)
        except Scan.DoesNotExist:
            row = None    
        except Scan.MultipleObjectsReturned:
            rows = Scan.objects.filter(Scan_Name=form["Scan_Name"].value)
            row = rows.first()
        form = ScanForm(request.POST, instance=row)    
        if form.is_valid():
            form.save()
            print("enter form is saved")
            Scans = Scan.objects.all()
            return render(request, "hello/ShowScans.html", {'scans' : Scans})# Redirect to your table view after saving
    else:
        print("enter 2")
        form = ScanForm()
    return render(request, "hello/ShowScans.html", {'scans': Scans})