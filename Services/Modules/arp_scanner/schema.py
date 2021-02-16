#!/usr/bin/env python3


# Imports
##############################################################################
from marshmallow import Schema, fields, validate
from validators import validate_ip_addr
##############################################################################


# Schema
##############################################################################
class ArpScannerGetSchema(Schema):
    target = fields.Str(required = True, validate = validate_ip_addr)
##############################################################################