###########################################
#       EmailHeaderExtractor.py           #
#       Coded by IlluminatiFish           #                  
###########################################                       

import requests, socket, warnings, re, ipaddress, base64, json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tld import get_tld

#Intialize all globally used variables

#Email header variables
sender = None
from_sender = None
return_path = None
reply_to = None
mailer = None
encoding = None
origin_ip = None
source_email_domain = None

route = []
domain_sources = []

whitelisted_domains =['www.w3.org', 'fonts.googleapis.com']
cleaned_urls = []

#VPN Detector variables
spans = []

#Decoding variables
string = None



######################################

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

def base64toString(base_string): #Convert base64 string to readable format
    return base64.b64decode(base_string).decode('utf-8')

def validateIPv4(ip): #Validate if IP is used and not private/loopback
    try:
        i = ipaddress.ip_address(ip)
        if i.is_global:
            return True
        return False
    except ValueError:
        return False

def gatherChain(url, verify_mode): #Gather the redirect chain of the url passed as a parameter

    response = None
    if verify_mode is False:
        response = requests.get(url, verify=False)
        print('[+] Attempting to gather redirect chain data mode: FALSE')

    if verify_mode is True:
        response = requests.get(url, verify=True)
        print('[+] Attempting to gather redirect chain data mode: TRUE')

    if response is not None:
        if response.history: #If the chain has any history
            print('  [+] Found {} redirects in chain'.format(len(response.history)))
            redirect = 0
            for resp in response.history:
                redirect += 1
                parser_object = urlparse(resp.url)
                if parser_object.netloc: #If domain is detected
                    try:
                        ip = socket.gethostbyname(parser_object.netloc) #Resolve to an IPv4
                    except Exception:
                        ip = None #Will give a null IP if the domain cannot be resolved

                    print('    - [Redirect: {}] [IP: {}] [Status: {}] - {}'.format(redirect, ip, resp.status_code, resp.url))
                else:
                    print('    [-] No netloc found in URL from request history')

            parser_object = urlparse(response.url)
            if parser_object.netloc: #If domain is detected
                try:
                    ip = socket.gethostbyname(parser_object.netloc)
                except Exception:
                    ip = None
            print('  [Effective URL] [IP: {}] [Status: {}] - {}'.format(ip, response.status_code, response.url))

        else:
            print('[-] No request history found, no redirects')
    else:
        print('[-] Failed to set any gatherChain mode as request object was null')

def chainDiscover(url): #Run the gatherChain function, use false mode incase of an exception
    try: #Initially try with TRUE mode
        gatherChain(url, True)
    except requests.exceptions.SSLError as ex: #If TRUE mode errors then it'll fallback to FALSE
        print('[-] Failed to gather redirect chain data using mode: TRUE [Err: {}]'.format(ex.__doc__))
        warnings.filterwarnings("ignore")
        gatherChain(url, False)

def domainExtraction(domain): #Need to recode
    res = get_tld('http://'+domain, as_object=True)
    domain = res.domain + '.' + res.tld
    return domain

def tracerouteDomain(route):
    counter = 1

    traceSize = len(route)
    print("[~] Email Traceroute (Domain) [{} hop(s)]:".format(traceSize))
    for domain in route:
        try:
            ip = socket.gethostbyname(domain)
        except socket.error:
            ip = None
        if counter == 1:
            print(" - [MSA]", domain ,"[IP: {}]".format(ip),"- (" + str(getInformation("ASN", domain)), "/",
                          str(getInformation("ISP", domain)), "/", str(getInformation("ORG", domain)) + ")")
        elif counter == traceSize:
            print(" - [MDA]", domain ,"[IP: {}]".format(ip),"- (" + str(getInformation("ASN", domain)), "/",
                          str(getInformation("ISP", domain)), "/", str(getInformation("ORG", domain)) + ")")
        else:
            print(" - [MTA-{}]".format(counter-1), domain ,"[IP: {}".format(ip),"- (" + str(getInformation("ASN", domain)), "/",
                          str(getInformation("ISP", domain)), "/", str(getInformation("ORG", domain)) + ")")
        counter += 1


def cleanHTML(raw_html):
  cleanr = re.compile('<.*?>')
  cleantext = re.sub(cleanr, '', str(raw_html))
  return cleantext.strip()


def getProvider(ip):
    spans.clear()
    r = requests.get('https://spur.us/context/{}'.format(ip))
    soup = BeautifulSoup(r.text, 'html.parser')
    for i in soup.find_all('span'):
        spans.append(i)
    if len(spans) > 1:
        if cleanHTML(spans[1]) == "Not Anonymous" or cleanHTML(spans[1]) == "Possibly Anonymous":
            return None
        return cleanHTML(spans[1])


def findURLs(string):
    if string is not None:

        p = re.compile(r'"(http.*?)"', re.MULTILINE|re.DOTALL)
        urls = re.findall(p, string)

        
        converted_list = [url.replace('\n', '') for url in urls] # We want to strip all elements in this list
        if len(converted_list) == 0:
            print('[-] No URLs were found in the body of the email!')
        else:
            print('[+] URLs found in body ({})'.format(len(converted_list)))
        for converted_url in converted_list:
            r = re.compile(r'^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$')
            m = re.search(r, converted_url.split('//')[1].split('/')[0])

            if m:
                if m.group() in whitelisted_domains:
                    pass
                else:
                    print('')
                    print('[+] Found URL in body:',converted_url)
                    try:
                        chainDiscover(converted_url)
                    except requests.exceptions.MissingSchema:
                        print('    [-] Missing URL scheme')
                    except requests.exceptions.InvalidURL:
                        print('    [-] Invalid URL scheme')
                        
def decodeMailBody(content_lines):
    split = content_lines.split('Content-Transfer-Encoding: '+str(encoding)+'\n\n')
    if encoding:
        print('[+] Decoding email body using {} encoding..'.format(encoding))

        if str(encoding) == 'base64':
            try:
                string = base64toString(split[len(split)-1])
            except UnicodeDecodeError:
                string = str(split[len(split)-1])

        if str(encoding) == '8bit':
            string = str(split[len(split)-1])

        if str(encoding) == '7bit':
            string = str(split[len(split)-1])
            #print(string)

        if str(encoding) == 'quoted-printable':
            string = str(split[len(split)-1])

        else:
            #print('[-] Could not find decoding method!')
            pass

    else:
        #print('[-] No encoding')
        string = str(split[len(split)-1])

    return string

def analyzeHeaders(header):
    global sender, from_sender, reply_to, return_path, mailer, encoding, origin_ip, route
    for header_line in header:

        if header_line.casefold().startswith('sender'):
            if 'sender: ' in header_line.casefold():
                data = header_line.split(': ')[1]
                sender = data

        if header_line.casefold().startswith('from:'):
            if 'from' in header_line.casefold():
                data = header_line.split(': ')[1]
                match = re.search(r"\S+@\S+", header_line)
                if match:
                    from_sender = match.group().replace('<', '').replace('>', '')

 

        if header_line.casefold().startswith('return-path'):
            if 'return-path' in header_line.casefold():
                data = header_line.split(': ')[1].replace('<', '').replace('>', '')
                return_path = data
 

        if header_line.casefold().startswith('reply-to'):
            if 'reply-to' in header_line.casefold():
                data = header_line.split(': ')[1]
                reply_to = data

        if header_line.casefold().startswith('message-id'):
            if 'message-id' in header_line.casefold():
                data = header_line.split(': ')[1]
                domain_msa = data.replace('<', '').replace('>', '').split('@')[1]
                if domain_msa != 'mx.google.com':
                    domain_sources.insert(0, domain_msa)


        if header_line.casefold().startswith('x-mailer'):
            if 'x-mailer' in header_line.casefold():
                if header_line.casefold() == 'x-mailer':
                    data = header_line.split(': ')[1]
                    mailer = data



        if header_line.casefold().startswith('user-agent'):
            if 'user-agent' in header_line.casefold():
                prefix = header_line.split(': ')[0]
                if prefix.casefold() == 'user-agent':
                    data = header_line.split(': ')[1]
                    mailer = data

        if header_line.casefold().startswith('content-transfer-encoding'):
            if 'content-transfer-encoding' in header_line.casefold():
                data = header_line.split(': ')[1]
                encoding = data

        if header_line.casefold().startswith('x-originating-ip'):
            if 'x-originating-ip' in header_line.casefold():
                data = header_line.split(': ')[1].replace('[', '').replace(']', '')
                origin_ip = data

        if header_line.casefold().startswith('received: from'):
            if 'received: from' in header_line.casefold():
                data = header_line.split(': from')[1]

                ipv4_pattern = re.compile(
                    r'(?:^|\b(?<!\.))(?:1?\d\d?|2[0-4]\d|25[0-5])(?:\.(?:1?\d\d?|2[0-4]\d|25[0-5])){3}(?=$|[^\w.])')  # need to strengthen the regex here
                ips = re.findall(ipv4_pattern, data)

                for ip in range(len(ips)):
                    if validateIPv4(ips[ip]):

                        if ips[ip] in route:
                            pass
                        else:

                            route.append(ips[ip])

                if 'prod.protection.outlook.com' in data:
                    continue

                domain = data.strip().split(' ')[0]
                m = re.search(r'(([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-z]{2,10})', domain)
                if m:
                    domain_sources.append(domain)


def getEmailBodyLines():
    global lines
    raw_body = open('body.txt', 'r', encoding='utf-8')
    raw_lines = raw_body.readlines()

    lines = ''

    for raw_line in raw_lines:
        lines += raw_line

    return lines

def getEmailBodyHeaders():
    global header
    raw_body = open('body.txt', 'r', encoding='utf-8')
    raw_lines = raw_body.readlines()

    lines = ''

    header = []
    for raw_line in raw_lines:
        lines += raw_line

    for line in lines.splitlines():
        if line != '':
            header.append(line)

    return header


def outputExtraction():
    print("")
    print("[~] Source Email:",from_sender)
    print('')
    source_mail_server = domain_sources[0]
    try:
        source_mail_server_ip = socket.gethostbyname(source_mail_server)
    except socket.error:
        source_mail_server_ip = None
    print("[~] Source Email Server:",source_mail_server, '(IP: {})'.format(source_mail_server_ip))
    print(" - ASN:",getInformation("ASN", source_mail_server))
    print(" - ISP:",getInformation("ISP", source_mail_server))
    print(" - ORG:",getInformation("ORG", source_mail_server))
    print('')
    print("[~] Mailer:",mailer)
    print("[~] Return To Email:",reply_to)
    print("[~] Return Path Email:",return_path)
    print('')
    tracerouteDomain(domain_sources)
    print('')
    if validateIPv4(origin_ip):
        if getProvider(origin_ip) is not None:
            provider = getProvider(origin_ip).replace(" ", "")+ "VPN"
        else:
            provider = None
        print("[~] Source IP:",origin_ip, "(VPN: {})".format(provider))
        print("  - ASN:",getInformation("ASN", origin_ip))
        print("  - ISP:",getInformation("ISP", origin_ip))
        print("  - ORG:",getInformation("ORG", origin_ip))
    else:
        pass

    print("[~] Notes:")
    if from_sender is not None:
        source_email_domain = from_sender.split('@')[1]
        try:
            source_email_domain_ip = socket.gethostbyname(source_email_domain)
        except socket.error:
            source_email_domain_ip = None


        print('')
        print(" - [FULL] Source Email Domain =", source_email_domain, '(IP: {})'.format(source_email_domain_ip))
        print("  - ASN:", getInformation("ASN", source_email_domain))
        print("  - ISP:", getInformation("ISP", source_email_domain))
        print("  - ORG:", getInformation("ORG", source_email_domain))



        #size = len(source_mail_server.split(".")) - 1 #Indexes of lists start at 0 so we must subtract 1

    print('')
    if(validateIPv4(source_mail_server) == False):
        email_server_domain = None
        if len(source_mail_server.split('.')) == 2:
            email_server_domain = source_mail_server
        else:
            email_server_domain = domainExtraction(source_mail_server)

        try:
            email_server_domain_ip = socket.gethostbyname(email_server_domain)
        except socket.error:
            email_server_domain_ip = None
        print(" - Source Email Server Domain =",email_server_domain,  '(IP: {})'.format(email_server_domain_ip)) #needs a bug fix

        print("  - ASN:",getInformation("ASN", email_server_domain))
        print("  - ISP:",getInformation("ISP", email_server_domain))
        print("  - ORG:",getInformation("ORG", email_server_domain))

    print('')
    #print(string)

#Main driver code starts here
print('[+] Analyzing headers..')
analyzeHeaders(getEmailBodyHeaders()) #Move to analyze headers when all headers are parsed from the input file

outputExtraction()

decoded = decodeMailBody(getEmailBodyLines())
print('[+] Searching for URLs in the email body')
findURLs(decoded)
