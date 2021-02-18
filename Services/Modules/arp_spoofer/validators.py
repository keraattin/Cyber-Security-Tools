#!/usr/bin/env python3


# Imports
##############################################################################
import re
##############################################################################


# Global Values
##############################################################################
IP_PATTERN = ("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

MAC_PATTRN = ("^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
##############################################################################


# Validate IP Address
##############################################################################
def validate_ip_addr(ip_addr):
    ip_matches = re.search(IP_PATTERN,ip_addr)
    if ip_matches:
        return True
    else:
        return False
##############################################################################


# Validate Mac Address
##############################################################################
def validate_mac_addr(mac_addr):
    matches = re.search(MAC_PATTRN,mac_addr)
    if matches:
        return True
    else:
        return False
##############################################################################