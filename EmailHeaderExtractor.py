import re, requests, ipaddress

def validateIP(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def reformatDomains(list_subdomains, size):     
    starting_index = len(list_subdomains) - size
    split_domain = list_subdomains[starting_index:]
    domain = ""
    for i in range(len(split_domain)):
        if i == len(split_domain) - 1:
            domain += split_domain[i]
            break
        domain += split_domain[i]+"."
    return domain

def getInformation(datatype, data):
    if data is None:
        return 
    else:
        url = "http://ip-api.com/json/{}".format(data)
        req = requests.get(url)
        reqjson = req.json()
        
        if str(datatype) == "ISP":
            try:
                isp = reqjson['isp']
                if len(isp) == 0:
                    isp = None
            except KeyError:
                isp = None
            return isp
            
        if str(datatype) == "ASN":
            try:
                asn = reqjson['as']
                if len(asn) == 0:
                    asn = None
            except KeyError:
                asn = None
            return asn
            
        if str(datatype) == "ORG":
            try:
                org = reqjson['org']
                if len(org) == 0:
                    org = None
            except KeyError:
                org = None
            return org
            
content = []
sources = []
response = {}
input("Enter email headers:\n")
while True:
    line = input()
    if line:
        content.append(line)
    else:
        break

emailer = None
source_mail_server = None
mailer = None
origin_ip = None
reply = None

for x in content:
    prefix = str(x.split(": ")[0]) 
    if 'Received' in x:
        if prefix == "Received":
            if 'Received: from' in x:
                if 'prod.protection.outlook.com' in x: #Patch for Outlook emails as they start with Outlook email protection domains instead of the actual domain that the email came from like seen on Gmail
                    continue

                source = x.replace('Received: from ', '').split(" ")[0]
                sources.append(source)

    if 'From' in x:
        if prefix == "From":
            d = re.split(r'\s{1,}', x)
            e = str(d[len(d)-1:len(d)])
            emailer = str(e.replace('<', '').replace('>', '').replace("['", "").replace("']", ""))

    if 'X-Mailer' in x:
        if prefix == "X-Mailer":
            data = x.split(": ")[1]
            mailer = data

    if 'User-Agent' in x:
        if prefix == 'User-Agent':
            data = x.split(": ")[1]
            mailer = data

    if 'X-Originating-IP' in x:
        if prefix == "X-Originating-IP":
            data = x.split(": ")[1]
            origin_ip = data.replace("[", "").replace("]", "")

    if 'Reply-To' in x:
        if prefix == "Reply-To":
            data = x.split(": ")[1]
            reply = data.replace('<', '').replace('>', '')  
    if 'Return-Path' in x:
        if prefix == "Return-Path":
            data = x.split(": ")[1]
            reply = data.replace('<', '').replace('>', '')       
            
print("")
print("=== Extraction Information ===")

print("[~] Source Email:",emailer)

source_mail_server = sources[0]
print("[~] Source Email Server:",source_mail_server)
print(" - ASN:",getInformation("ASN", source_mail_server))
print(" - ISP:",getInformation("ISP", source_mail_server))
print(" - ORG:",getInformation("ORG", source_mail_server))

print("[~] Mailer:",mailer)

print("[~] Source IP:",origin_ip)
print("  - ASN:",getInformation("ASN", origin_ip))
print("  - ISP:",getInformation("ISP", origin_ip))
print("  - ORG:",getInformation("ORG", origin_ip))

print("[~] Return Email:",reply)

print("[~] Notes:")

source_email_domain = emailer.split('@')[1]
print(" - Source Email Domain =",source_email_domain)
print("  - ASN:",getInformation("ASN", source_email_domain))
print("  - ISP:",getInformation("ISP", source_email_domain))
print("  - ORG:",getInformation("ORG", source_email_domain))

size = len(source_mail_server.split(".")) - 1 #Indexes of lists start at 0 so we must subtract 1

if(validateIP(source_mail_server) == False):
    email_server_domain = reformatDomains(source_mail_server.split("."), size)
    print(" - Source Email Server Domain =",email_server_domain)

    print("  - ASN:",getInformation("ASN", email_server_domain))
    print("  - ISP:",getInformation("ISP", email_server_domain))
    print("  - ORG:",getInformation("ORG", email_server_domain))

