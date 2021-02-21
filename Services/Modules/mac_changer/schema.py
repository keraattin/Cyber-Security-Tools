#!/usr/bin/env python3


# Imports
##############################################################################
from marshmallow import Schema, fields, validate
from .validators import validate_mac_addr
##############################################################################


# Schema
##############################################################################
class MacChangerPostSchema(Schema):
    iface     = fields.Str(required = True)
    mac_addr  = fields.Str(required = True, validate = validate_mac_addr)
##############################################################################