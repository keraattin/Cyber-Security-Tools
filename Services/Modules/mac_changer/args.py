#!/usr/bin/env python3


# Imports
##############################################################################
from flask_restful import reqparse
##############################################################################


# Args
##############################################################################
mac_changer_post_args = reqparse.RequestParser()
mac_changer_post_args.add_argument("iface",  type=str, 
        help="Interface",  required=True)
mac_changer_post_args.add_argument("mac_addr", type=str, 
        help="New MAC Adress", required=True)
##############################################################################