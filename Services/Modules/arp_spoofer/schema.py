#!/usr/bin/env python3


# Imports
##############################################################################
from marshmallow import Schema, fields, validate
from .validators import validate_ip_addr
##############################################################################


# Schema
##############################################################################
class ArpSpooferPostSchema(Schema):
    target_ip_addr  = fields.Str(required = True, validate = validate_ip_addr)
    target_mac_addr = fields.Str(required = True, validate = validate_ip_addr)
    router_ip_addr  = fields.Str(required = True, validate = validate_ip_addr)
    router_mac_addr = fields.Str(required = True, validate = validate_ip_addr)

class ArpSpooferDeleteSchema(Schema):
    target_ip_addr  = fields.Str(required = True, validate = validate_ip_addr)
##############################################################################