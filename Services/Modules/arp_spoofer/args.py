#!/usr/bin/env python3


# Imports
##############################################################################
from flask_restful import reqparse
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

arp_spoof_delete_args = reqparse.RequestParser()
arp_spoof_delete_args.add_argument("target_ip_addr",type=str, 
        help="Target Ip Adress",  required=True)
##############################################################################