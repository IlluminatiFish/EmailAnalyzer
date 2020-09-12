###########################################
#       EmailHeaderExtractor.py           #
#       Coded by IlluminatiFish           #                  
###########################################                       

import re
import requests
import ipaddress
import json

def validateIP(ip):
    try:
        i = ipaddress.ip_address(ip)
        if i.is_global:
            return True
        return False
    except ValueError:
        return False

def domainExtraction(domain):
    if len(domain.split('.')) == 2: #Domain only has one dot meaning its the actual domain
        return domain #Return the domain given
    elif len(domain.split('.')) > 2:
        o = domain.split('.', 1) #Split at the first dot seen
        output = o[1]
        return output #Output the domain without the front bit
        
def getInformation(datatype, data):
    if data is None:
        return 
    else:
        url = "http://ip-api.com/json/{}".format(data)
        req = requests.get(url)
        try:
            reqjson = req.json()
        except json.decoder.JSONDecodeError as err:
            print('JSON Error, unable to gather info on ip/domain')
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
ips = []
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

                ip_pattern = re.compile(r'(?:^|\b(?<!\.))(?:1?\d\d?|2[0-4]\d|25[0-5])(?:\.(?:1?\d\d?|2[0-4]\d|25[0-5])){3}(?=$|[^\w.])') # need to strengthen the regex here
                ip = re.findall(ip_pattern, x)
                
                for i in range(len(ip)):
                    if validateIP(ip[i]):
                        if ip[i] in ips:
                            pass
                            #print("List Error, this IP address is already in the traceroute list!")
                        else:
                            ips.append(ip[i])
                               
                if 'prod.protection.outlook.com' in x: #Patch for Outlook emails as they start with Outlook email protection domains instead of the actual domain that the email came from like seen on Gmail
                    continue
                
                source = x.replace('Received: from ', '').split(" ")[0]
                sources.append(source)
                



    if 'from' in x.casefold():
        if prefix.casefold() == "from":
            d = re.split(r'\s{1,}', x)
            e = str(d[len(d)-1:len(d)])
            emailer = str(e.replace('<', '').replace('>', '').replace("['", "").replace("']", ""))

    if 'x-mailer' in x.casefold():
        if prefix.casefold() == "x-mailer":
            data = x.split(": ")[1]
            mailer = data

    if 'user-agent' in x.casefold():
        if prefix.casefold() == 'user-agent':
            data = x.split(": ")[1]
            mailer = data

    if 'x-originating-ip' in x.casefold():
        if prefix.casefold() == "x-originating-ip":
            data = x.split(": ")[1]
            origin_ip = data.replace("[", "").replace("]", "")

    if 'reply-to' in x.casefold():
        if prefix.casefold() == "reply-to":
            data = x.split(": ")[1]
            reply = data.replace('<', '').replace('>', '')  
    if 'return-path' in x.casefold():
        if prefix.casefold() == "return-path":
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

print("[~] Return Email:",reply)


z = 1
x = len(ips)
print("[~] Email Traceroute [{} hop(s)]:".format(len(ips)))

for ip in ips:
    
    if z == 1:
        print(" [SOURCE MAIL SERVER] "+str(z)+":",ip,"- ("+str(getInformation("ASN", ip)),"/",str(getInformation("ISP", ip)),"/",str(getInformation("ORG", ip))+")")
    else:
        if x == z:
            if origin_ip is None:
                origin_ip = ips[x-1]
                print(" [SOURCE USER IP] "+str(z)+":",ip,"- ("+str(getInformation("ASN", ip)),"/",str(getInformation("ISP", ip)),"/",str(getInformation("ORG", ip))+")")
            else:
                print(" [-] "+str(z)+":",ip,"- ("+str(getInformation("ASN", ip)),"/",str(getInformation("ISP", ip)),"/",str(getInformation("ORG", ip))+")")
        else:
            print(" [-] "+str(z)+":",ip,"- ("+str(getInformation("ASN", ip)),"/",str(getInformation("ISP", ip)),"/",str(getInformation("ORG", ip))+")")
    z += 1

if(validateIP(origin_ip) == False):
    pass
else:
    print("[~] Source IP:",origin_ip)
    print("  - ASN:",getInformation("ASN", origin_ip))
    print("  - ISP:",getInformation("ISP", origin_ip))
    print("  - ORG:",getInformation("ORG", origin_ip))

print("[~] Notes:")    

source_email_domain = emailer.split('@')[1]
print(" - Source Email Domain =",source_email_domain)
print("  - ASN:",getInformation("ASN", source_email_domain))
print("  - ISP:",getInformation("ISP", source_email_domain))
print("  - ORG:",getInformation("ORG", source_email_domain))

size = len(source_mail_server.split(".")) - 1 #Indexes of lists start at 0 so we must subtract 1

if(validateIP(source_mail_server) == False):
    email_server_domain = domainExtraction(source_mail_server)
    print(" - Source Email Server Domain =",email_server_domain) #needs a bug fix

    print("  - ASN:",getInformation("ASN", email_server_domain))
    print("  - ISP:",getInformation("ISP", email_server_domain))
    print("  - ORG:",getInformation("ORG", email_server_domain))

