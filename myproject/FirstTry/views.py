import datetime
import time
from celery import Celery, shared_task
from django.http import HttpResponse
import subprocess
from .forms import TaskForm ,HomeForm , SignupForm , LoginForm , ResultatVulnersForm,ResultatTCPForm   # Assurez-vous d'importer les formulaires
import xml.etree.ElementTree as ET
from FirstTry.models import Home,ResultatTCP, ScanPorts, ScanVulnerabilities,Schedule,Target
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from celery.result import AsyncResult
from django.contrib.contenttypes.models import ContentType
# Create your views here.


app = Celery('myproject', backend='redis://localhost')

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


def indexwithout(request):
    time.sleep(10)
    return render(request,"hello/Home.html")

def AddTask(request):
    schedule = Schedule.objects.all()
    targets = Target.objects.all()
    context = {'choices': schedule ,'targets':targets}
    return render(request,"hello/NewTask.html",context)

@shared_task
def runCommand(taskForm) :
    
    Type = taskForm['scan_type']
    db = taskForm["dataBase"]
    IpAddress = taskForm["ip_address"]
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
        scan_form = TaskForm(request.POST)
     
        if scan_form.is_valid():
            # Sauvegarder les données du formulaire
            scan_form.save()
            your_view(request)

    else:
        scan_form = TaskForm()
   
    return render(request, "hello/NewTask.html", {'scan_form': scan_form})
    

def ShowResultsTCP(request):
    return render(request, "hello/TcpPingResults.html")


def byScanType(request):
    taskForm = TaskForm(request.POST)
    runCommand(taskForm)
    # Chemin vers le fichier XML généré par Nmap
    xml_file_path = 'output.xml'
    
    if taskForm['scan_type'].value() == "-sT":
        # Exécutez le scan Nmap et extrayez les informations du fichier XML
        ports_info = parseNmapXmlCaseTcpPing(xml_file_path)
        # Passez les informations extraites au template
        return render(request, 'hello/ind.html', {'ports_info': ports_info})
    else:
        return HttpResponse("scan type n'est pas TCP Ping")

def your_view(request):

    taskForm = TaskForm(request.POST)
    
    if taskForm.is_valid():
        task = form.save(commit=False)
        task.target = taskForm.cleaned_data['target']
        task.Configuration = taskForm.cleaned_data['Configuration']
        task.schedule = taskForm.cleaned_data['schedule']
        content_type = taskForm.cleaned_data['content_type']
        scan_id = form.cleaned_data['object_id']

        if content_type == ContentType.objects.get_for_model(ScanPorts):
            related_object = ScanPorts.objects.get(pk=scan_id)
        elif content_type == ContentType.objects.get_for_model(ScanVulnerabilities):
            related_object = ScanVulnerabilities.objects.get(pk=scan_id)
        
        task.content_object = related_object

        task.save()

        # # Sauvegarder les données du formulaire
        # homeForm = HomeForm({
        #         'name_scan': taskForm['name'].value(),
        #         'status': "Done",
        #         'ip_address_scan':taskForm['ip_address'].value(),
        # }   
        # )
        # homeForm.save()
        
        d=0
        
        duration = taskForm['recurrence'].value()
        if duration == "daily":
            d = 1
        elif duration == "weekly":
            d = 7
        elif duration == "yearly":
            d = 365
        elif duration == "monthly":
            d = 30
        elif duration == "none":
            d=0

        taskForm_serializable = {
            'ip_address':taskForm['ip_address'].value(),
            'name': taskForm['name'].value(),
            'scan_type': taskForm['scan_type'].value(),
            'dataBase':taskForm['dataBase'].value(),
            'start_time': taskForm['start_time'].value(),
            'recurrence' : taskForm['recurrence'].value(),
        }
        scan_datetime = taskForm.cleaned_data['start_time']
        current_datetime = datetime.datetime.now(datetime.timezone.utc)

        if scan_datetime >= current_datetime:
            time_diff = (scan_datetime - current_datetime).total_seconds()

            #pour la fonction périodique.
            time_diff_period = (scan_datetime+datetime.timedelta(days=d) - datetime.datetime.now(datetime.timezone.utc)).total_seconds()


            print("Waiting for initial scheduled scan at:", scan_datetime.strftime("%Y-%m-%d %H:%M:%S"))
            print("Time left:", datetime.timedelta(seconds=time_diff))

            target=taskForm['ip_address'].value()

            print("target is : ",target)
            print("current:", current_datetime.strftime("%Y-%m-%d %H:%M:%S"))

            ports_info_result = scheduled_periodic_scan.apply_async(args=(taskForm_serializable,), countdown=time_diff)


            data = Home.objects.all()
            return render(request,'hello/DisplayScans.html',{'data': data}) # Redirect to status polling view
        else:
            return HttpResponse("probleme du temps.")
    else:   
        return HttpResponse("scan n'est pas valide")

# views.py
from django.http import JsonResponse
def AddSchedule(request):

    return render(request , 'hello/NewSchedule.html')

def check_task_result(request):
    # Get the task ID from the session or database
    task_id = request.session.get('task_id')
    # or
    # task_id = YourModel.objects.get(...).task_id

    if task_id:
        task = AsyncResult(task_id)
        if task.ready():
            task_result = task.get()
            # Process the result and display a notification
            notification = {
                'status': 'success',
                'message': 'Scan completed successfully.',
                'result': task_result
            }
        else:
            # Task is not yet completed
            notification = {
                'status': 'pending',
                'message': 'Scan is still in progress. Please wait.'
            }
    else:
        notification = {
            'status': 'error',
            'message': 'No task found.'
        }

    return JsonResponse(notification)

@shared_task
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

            extracted_table.append({'nameVuln': id,
                         'cvss': cvss,
                          'type':Type,
                          'is_exploit':isExploitable
                          })

        
        return extracted_table

    except Exception as e:

        return extracted_table 
    

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
        return []   
       

    # runCommand(taskForm)
    # match Data:
    
    #     case "vuln":
            
    #         return HttpResponse(Data)
                    
    #     case "vulners":
    #             # Exécutez le scan Nmap et extrayez les informations du fichier XML
    #         ports_info = parseNmapXmlCaseVulners(request,xml_file_path)
    #             # Passez les informations extraites au template
    #         return render(request, 'hello/ShowResults.html', {'ports_info': ports_info})
        
    #     case "Simple Scan":
            
    #         ports_info = parseNmapXmlCaseTcpPing(request,xml_file_path)
    #         # Passez les informations extraites au template
    #         return render(request, 'hello/TcpPingResults.html', {'ports_info': ports_info})

    
@shared_task
def scheduled_periodic_scan(taskForm):
        print("Initial scheduled scan started at:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        Data = taskForm['dataBase']
        Type = taskForm['scan_type']
        db = taskForm["dataBase"]
        IpAddress = taskForm["ip_address"]
        if db == "Simple Scan":
            command = "nmap -oX output.xml "+ Type +" "+ IpAddress
        else:
            command = "nmap -oX output.xml -sV --script "+db+" "+IpAddress

        try:
            subprocess.run(command, shell=True, check=True)
            
        except subprocess.CalledProcessError as e:
            print(e)
            
        xml_file_path = 'output.xml'
        match db:
    
            case "vuln":
                
                return HttpResponse(Data)
                        
            case "vulners":
                    
                ports_info = parseNmapXmlCaseVulners(xml_file_path)
                resultats = ResultatVulnersForm()
                for result in ports_info:
                    resultats = ResultatVulnersForm({
                            'vulnerability': result.get('nameVuln', ''),
                            'severity': result.get('cvss', ''),
                            'type': result.get('type', ''),
                            'is_exploit': result.get('is_exploit', False),
                    })
                
                    resultats.save()
                
            case "Simple Scan":
                
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



        return ports_info
