# Written by: Predrag Petrovic <ppetrovic@paloaltonetworks.com>
# Purpose:
# This script is written to migrate Azure Firewall policies and IP Groups
# to PAN-OS configuration using Expedition2.
# To-Do:
# 1) BETTER ERROR HANDLING
# 2) CODE CLEANUP


import json, requests, urllib3, os, ipaddress, re, getpass, csv, colorama
from time import sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def clearScreen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


clearScreen()

USERNAME = input('Please enter your username: ')
PASSWORD = getpass.getpass(prompt='Please input your password: ')
HOSTNAME = input(
    'Please input the hostname where Expedition2 is running\n(eg. 127.0.0.1 ; localhost ; localhost:4434): ')

# Azure Service Tags
# to get the list issue:
# az network list-service-tags --location westus2 --query 'values[].properties.{systemService: systemService}' | tr -d '{}[\t ]' | sed 's/\"systemService\"://' | sort | uniq

azureTags = ["ActionGroup", "ApplicationInsightsAvailability", "AutonomousDevelopmentPlatform", "AzureAD",
             "AzureAPIForFHIR", "AzureAdvancedThreatProtection", "AzureApiManagement", "AzureAppConfiguration",
             "AzureAppService", "AzureAppServiceManagement", "AzureArcInfrastructure", "AzureAttestation",
             "AzureAutomation", "AzureBackup", "AzureBotService", "AzureCognitiveSearch", "AzureConnectors",
             "AzureContainerAppsService", "AzureContainerRegistry", "AzureCosmosDB", "AzureDataExplorerManagement",
             "AzureDataLake", "AzureDatabricks", "AzureDevOps", "AzureDevSpaces", "AzureDeviceUpdate",
             "AzureDigitalTwins", "AzureEventGrid", "AzureEventHub", "AzureFrontDoor", "AzureIdentity",
             "AzureInformationProtection", "AzureIoTHub", "AzureKeyVault", "AzureLoadTestingInstanceManagement",
             "AzureMachineLearning", "AzureManagedGrafana", "AzureMonitor", "AzureOpenDatasets", "AzurePortal",
             "AzureRemoteRendering", "AzureResourceManager", "AzureSQL", "AzureSecurityCenter", "AzureSentinel",
             "AzureServiceBus", "AzureSignalR", "AzureSiteRecovery", "AzureSphereSecureService_Prod",
             "AzureSpringCloud", "AzureStack", "AzureStorage", "AzureTrafficManager", "AzureUpdateDelivery",
             "AzureVideoAnalyzerForMedia", "AzureWebPubSub", "BatchNodeManagement", "ChaosStudio",
             "CognitiveServicesFrontend", "CognitiveServicesManagement", "DataFactory", "Dynamics365BusinessCentral",
             "Dynamics365ForMarketingEmail", "Dynamics365FraudProtection", "EOPExtPublished", "GatewayManager",
             "GenevaActions", "Grafana", "HDInsight", "LogicApps", "M365ManagementActivityApi",
             "M365ManagementActivityApiWebhook", "Marketplace", "MicrosoftAzureFluidRelay", "MicrosoftCloudAppSecurity",
             "MicrosoftContainerRegistry", "MicrosoftDefenderForEndpoint", "MicrosoftPurviewPolicyDistribution",
             "OneDsCollector", "PowerBI", "PowerPlatformInfra", "PowerPlatformPlex", "PowerQueryOnline", "SCCservice",
             "ServiceFabric", "SqlManagement", "StorageSyncService", "TridentKusto", "WindowsAdminCenter",
             "WindowsVirtualDesktop"]

# Azure Firewall FQDN tags
# to get the list issue:
# az network firewall list-fqdn-tags --query '[].fqdnTagName' | tr -d '{,"}[\t ]'

azureFirewallTags = ["AppServiceEnvironment", "AzureBackup", "AzureKubernetesService", "HDInsight",
                     "MicrosoftActiveProtectionService", "MicrosoftIntune", "Windows365", "WindowsDiagnostics",
                     "WindowsUpdate", "WindowsVirtualDesktop", "citrixHdxPlusForWindows365",
                     "Office365.Exchange.Optimize", "Office365.Exchange.Default.Required",
                     "Office365.Exchange.Allow.Required", "Office365.Skype.Allow.Required",
                     "Office365.Skype.Default.Required", "Office365.Skype.Default.NotRequired",
                     "Office365.Skype.Allow.NotRequired", "Office365.SharePoint.Optimize",
                     "Office365.SharePoint.Default.NotRequired", "Office365.SharePoint.Default.Required",
                     "Office365.Common.Default.NotRequired", "Office365.Common.Allow.Required",
                     "Office365.Common.Default.Required"]

# Azure Firewall Web Categories
# https://learn.microsoft.com/en-us/azure/firewall/web-categories

getApiKeyUrl = 'https://' + HOSTNAME + '/api/v1/generate_api_key'
baseObjectUrl = 'https://' + HOSTNAME + '/api/v1/'


def getToken(url, USERNAME, PASSWORD):
    data = {
        "username": USERNAME,
        "password": PASSWORD
    }

    r = requests.post(url, data=data, verify=False)
    response = r.json()
    success = json.dumps(response["success"])

    if success == "true":
        api_key = json.dumps(response['data']['api_key'])
        return api_key.replace('"', '')

    else:
        print("Unable to get api key")


token = getToken(getApiKeyUrl, USERNAME, PASSWORD)
print(token)


def printProjects(token):
    authdata = {
        "Authorization": "Bearer " + token,
    }

    rProjects = baseObjectUrl + 'project'
    r = requests.get(rProjects, headers=authdata, verify=False)
    rJ = r.json()

    return rJ

def getDeviceGroups(token, pId):
    authdata = {
        "Authorization": "Bearer " + token,
    }

    rDGs = baseObjectUrl + 'project/' + pId + '/device_group'
    r = requests.get(rDGs, headers=authdata, verify=False)
    rJ = r.json()

    return rJ

def createObjectToId():
    with open('object_to_id.csv', mode="w", newline="") as csv_file:
        fieldnames = ['object_type', 'object_name', 'objectId']
        writer = csv.writer(csv_file, delimiter=";")
        writer.writerow(fieldnames)

def appendObjectToId(object_type, object_value, objectId):
    with open('object_to_id.csv', mode="a", newline="") as csv_file:
        writer = csv.writer(csv_file, delimiter=";")
        row = [object_type, object_value, objectId]
        writer.writerow(row)

def printSources(token, projectId):
    authdata = {
        "Authorization": "Bearer " + token,
    }

    rSources = baseObjectUrl + 'project/' + str(projectId) + '/source'
    r = requests.get(rSources, headers=authdata, verify=False)
    response = r.json()
    print(token)
    return (response)


def sanitize_name(input_data):
    input_data = input_data[:63]
    input_data = re.sub("[^A-Z,0-9,\s]", "", input_data, 0, re.IGNORECASE)
    return input_data


def parse_cidr(ip_str):
    try:
        ip = ipaddress.IPv4Network(ip_str)
        return str(ip.network_address), str(ip.prefixlen).lstrip('/')

    except ValueError:
        return ip_str, "/32"


def createFqdnObject(token, projectId, sourceId, vSysId, value):
    authdata = {
        "Authorization": "Bearer " + token,
    }

    data = {
        'source': sourceId,
        'vsys': vSysId,
        'name': value,
        'type': 'fqdn',
        'ipaddress': value,
    }

    url = baseObjectUrl + 'project/' + str(projectId) + '/object/address'

    r = requests.post(url, verify=False, headers=authdata, data=data)
    response = r.json()
    success = json.dumps(response["success"])
    if success == "true":
        objects = json.dumps(response['data'])
        print(objects)
        addressId = json.dumps(response['data']['id'])
        appendObjectToId('address', str(value), addressId)

    else:
        objects = json.dumps(response)
        print(objects)
        print("Unable to create object ")


def createAddressObject(token, projectId, sourceId, vSysId, value):
    authdata = {
        "Authorization": "Bearer " + token,
    }

    if '-' in value:
        name = value.replace('-', '--')
        name = name.replace('.', '-')
        name = 'rng_' + name
        data = {
            'source': sourceId,
            'vsys': vSysId,
            'name': name,
            'type': 'ip-range',
            'ipaddress': value,
            'ip_type': 'ipv4',
        }

    else:
        name = value
        name = name.replace('.', '-')
        name = name.replace('/', '--')
        nx = 'ao_' + name

        ip, cidr = parse_cidr(value)
        data = {
            'source': sourceId,
            'vsys': vSysId,
            'name': nx,
            'type': 'ip-netmask',
            'ipaddress': ip,
            'ip_type': 'ipv4',
            'netmask': cidr,
        }

    url = baseObjectUrl + 'project/' + str(projectId) + '/object/address'

    r = requests.post(url, verify=False, headers=authdata, data=data)
    response = r.json()
    success = json.dumps(response["success"])
    if success == "true":
        objects = json.dumps(response['data'])
        addressId = json.dumps(response['data']['id'])
        appendObjectToId('address', str(value), addressId)
        print(objects)

    else:
        print("Unable to create object ")

def createServiceObject(token, projectId, sourceId, vSysId, proto, value):
    authdata = {
        "Authorization": "Bearer " + token,
    }

    data = {
        "source": sourceId,
        "vsys": vSysId,
        "name": "so_" + str(proto) + '_' + str(value),
        "protocol": proto,
        "dst_port": value,
    }

    url = baseObjectUrl + 'project/' + str(projectId) + '/object/service'

    r = requests.post(url, verify=False, headers=authdata, data=data)
    response = r.json()
    success = json.dumps(response["success"])
    if success == "true":
        objects = json.dumps(response['data'])
        serviceId = json.dumps(response['data']['id'])
        appendObjectToId('service-'+str(proto), str(value), serviceId)
    else:
        print("Unable to create object ")


def createUrlCategory(token, projectId, sourceId, vSysId, urlCatName, members):
    authdata = {
        "Authorization": "Bearer " + token,
    }
    url = baseObjectUrl + 'project/' + str(projectId) + '/object/profile'
    xml_base = '<entry name=\"' + str(urlCatName) + '\">\n<list>\n'
    xml_end = '</list>\n<type>URL List</type>\n<description>Migration</description></entry>'
    xml_middle = ""
    for member in members:
        print(member)
        xml_middle = xml_middle + '<member>' + member + '/</member>\n'
    xml_data = xml_base + xml_middle + xml_end
    data = {
        "name": urlCatName,
        "description": "Migration",
        "source": sourceId,
        "vsys": vSysId,
        "object-type": "profile",
        "type": "custom-url-category",
        "xml": xml_data,
    }
    r = requests.post(url, verify=False, headers=authdata, data=data)
    response = r.json()
    urlId = json.dumps(response['data']['id'])
    appendObjectToId('url-category', urlCatName, urlId)

def createGroup(token, projectId, data, name):
    authdata = {
        "Authorization": "Bearer " + token,
    }

    url = baseObjectUrl + 'project/' + str(projectId) + '/object/address_group'
    r = requests.post(url, headers=authdata, data=data, verify=False)
    response = r.json()
    groupId = json.dumps(response['data']['id'])
    appendObjectToId('group', name, groupId)

def processGroups(token, directory, projectId, sourceId, vSysId):
    if os.path.isdir(directory):
        file_list = os.listdir(directory)
        for file_name in file_list:
            file_path = os.path.join(directory, file_name)
            if os.path.isfile(file_path):
                sourceIds = []
                name = os.path.splitext(file_name)[0]
                with open(file_path, "r") as file:
                    for line in file:
                        x = line.strip()
                        createAddressObject(token, projectId, sourceId, vSysId, x)
                        sourceIds.append(searchCSV('address', x))
                data = {
                    "source": sourceId,
                    "vsys": vSysId,
                    "name": name,
                    "type": 'static',
                }
                for y, value in enumerate(sourceIds):
                    data[f'member[{y}]'] = value
                createGroup(token, projectId, data, name)
                        
def returnServiceObjectId(token, projectId, sourceId, vSysId, protocol, port):
    authdata = {
        "Authorization": "Bearer " + token,
    }

    url = baseObjectUrl + 'project/' + str(projectId) + '/object/service'
    r = requests.get(url, verify=False, headers=authdata)
    response = r.json()
    results = response['data']
    for x in results['service']:
        if x['vsys'] == int(vSysId) and x['source'] == int(sourceId) and x['protocol'] == str(protocol) and \
                x['dst_port'] == str(port):
            return (x['id'])

def createGroups():
    print('test')

def searchCSV(object_type, object_name):
    with open('object_to_id.csv', 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=';')
        for row in reader:
            if row['object_type'] == object_type and row['object_name'] == object_name:
                return row['objectId']

def buildUrlPolicy(ruleName, sourceId, vSysId, action, sources, services, urlCatId):
    data = {
        'name': ruleName,
        'source': sourceId,
        'vsys': vSysId,
        'object_type': 'security_rule',
        'log_start': 0,
        'log_end': 1,
        'preorpost': 0,
        'rule_type': 'universal',
        'where': 'bottom',        
        'profile_type': 'None',
        'profile': [],
        'action': action,
        'category[0]': urlCatId,
    }
    for x, value in enumerate(sources):
        data[f'source_address[{x}]'] = value
    for x, value in enumerate(services):
        data[f'source_address[{x}]'] = value
    
    return data

def buildServicePolicy(ruleName, sourceId, vSysId, sources, destinations,services,action):

    data = {
        'name': ruleName,
        'source': sourceId,
        'vsys': vSysId,
        'object_type': 'security_rule',
        'log_start': 0,
        'log_end': 1,
        'preorpost': 0,
        'rule_type': 'universal',
        'where': 'bottom',
        'profile_type': 'None',
        'profile': [],
        'action': action,
    }

    for x, value in enumerate(sources):
        data[f'source_address[{x}]'] = value
    for x, value in enumerate(destinations):
        data[f'destination_address[{x}]'] = value
    for x, value in enumerate(services):
        data[f'service[{x}]'] = value

    return data

def createSecurityRule(token, projectId, data):
    authdata = {
        "Authorization": "Bearer " + token,
    }

    url = baseObjectUrl + 'project/' + str(projectId) + '/policy/security'
    r = requests.post(url, verify=False, headers=authdata, data=data)
    response = r.json()

def processCSVRule(rule):
    sourceIds = []
    destIds = []
    portIds = []
    tcp_ports = []
    udp_ports = []
    destinations = []
    sources = []
    sourceGroups = []
    destGroups = []
    urls = []

    if rule['ruleType'] == 'NetworkRule':
        print(rule['UUID'])
        if rule['sourceAddress'] != '':
            sources = rule['sourceAddress'].split(',')
        if rule['sourceGroup'] != '':
            sourceGroups = rule['sourceGroup'].split(',')
        if rule['destinationAddress'] != '':
            destinations = rule['destinationAddress'].split(',')
        if rule['destinationGroup'] != '':
            destGroups = rule['destinationGroup'].split(',')
        if rule['destinationFqdn'] != '':
            destinations = rule['destinationFqdn'].split(',')
        if 'TCP' in rule['ipProtocols'] or 'ANY' in rule['ipProtocols']:
            tcp_ports = rule['destinationPorts'].split(',')
        if 'UDP' in rule['ipProtocols'] or 'ANY' in rule['ipProtocols']:
            udp_ports = rule['destinationPorts'].split(',')
        for source in sources:
            x = searchCSV('address', source.strip())
            print(x)
            sourceIds.append(x)
        for group in sourceGroups:
            x = searchCSV('group', group.strip())
            print(x)
            print(group)
            sourceIds.append(x)
        for dest in destinations:
            x = searchCSV('address', dest.strip())
            print(x)
            destIds.append(x)
        for group in destGroups:
            print(group)
            x = searchCSV('group', group.strip())
            print(x)
            destIds.append(x)
        for port in udp_ports:
            x = searchCSV('service-udp', port)
            portIds.append(x)
        for port in tcp_ports:
            x = searchCSV('service-tcp', port)
            portIds.append(x)
        if rule['ruleAction'] == 'Allow':
            action = "allow"
        elif rule['ruleAction'] == 'Deny':
            action = "drop"
        rule = buildServicePolicy(rule['ruleName'], sourceId, vSysId, sourceIds, destIds, portIds , action)
        createSecurityRule(token, pId, rule)

    elif rule['ruleType'] == 'ApplicationRule':
        print(rule['UUID'])
        if rule['sourceAddress'] != '':
            sources = rule['sourceAddress'].split(',')
        if rule['sourceGroup'] != '':
            sourceGroups = rule['sourceGroup'].split(',')
        if rule['targetFqdns'] != '':
            urls = rule['targetFqdns'].split(',')
        for source in sources:
            x = searchCSV('address', source.strip())
            print(x)
            sourceIds.append(x)
        for group in sourceGroups:
            x = searchCSV('group', group.strip())
            sourceIds.append(x)
        if rule['ruleAction'] == 'Allow':
            action = "allow"
        elif rule['ruleAction'] == 'Deny':
            action = "drop"
        createUrlCategory(token, pId, sourceId, vSysId, rule['ruleName'], urls)
        urlCatId = searchCSV('url-category', rule['ruleName'])
        services = []
        rule = buildUrlPolicy(rule['ruleName'], sourceId, vSysId, action, sourceIds, services, urlCatId)
        createSecurityRule(token, pId, rule)

print("Current available projects are")
print("*" * 50)
for project in printProjects(token)['data']['project']:
    print("* Project name: " + str(project['name']) + "\n* Project ID: " + str(
        project['id']) + "\n* Project Description: " + str(project['description']))
    print("*" * 50)

pId = input('Please input project id: ')
print("*" * 50)
for source in printSources(token, pId)['data']['source']:
    print('* Source Name: ' + source['name'] + '\nSource ID: ' + str(source['id']))
    print("*" * 50)
for vSys in getDeviceGroups(token, pId)['data']['device_group']:
    print('DG name: ' + str(vSys['name']) + "\nDG ID: " + str(vSys['id']))
    print("*" * 50)

sourceId = input('Please select a source ID: ')
vSysId = input('Please select DG ID: ')

# populating object ID's for the security rules

#createSecurityRule(token, pId, sourceId, vSysId)
createObjectToId()
tcpPortId = []
udpPortId = []
sourceAOId = []
destAOId = []

with open('udp_ports.txt', 'r') as file:
    for line in file:
        x = line.strip()
        createServiceObject(token, pId, sourceId, vSysId, 'udp', x)

with open('tcp_ports.txt', 'r') as file:
    for line in file:
        x = line.strip()
        createServiceObject(token, pId, sourceId, vSysId, 'tcp', x)

with open('addresses.txt', 'r') as file:
    for line in file:
        x = line.strip()
        if not x:
            continue
        createAddressObject(token, pId, sourceId, vSysId, x)

with open('fqdns.txt', 'r') as file:
    for line in file:
        x = line.strip()
        createFqdnObject(token, pId, sourceId, vSysId, x)

processGroups(token, 'groups', pId, sourceId, vSysId)

with open('firewall_rules_export.csv', 'r') as rules:
    reader = csv.DictReader(rules,  delimiter=';')
    for row in reader:
        processCSVRule(row)

print(token)