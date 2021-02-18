#!/usr/bin/env python3


# Imports
##############################################################################
import re
##############################################################################


# Global Values
##############################################################################
IP_SUBNET_PATTERN = ("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\/([1-9]|[1][0-9]|[2][0-9]|[3][0-2])$")

IP_PATTERN = ("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

MAC_PATTRN = ("^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
##############################################################################


# Validate Target IP Address
##############################################################################
def validate_ip_addr(ip_addr):
    ip_matches = re.search(IP_PATTERN,ip_addr)
    ip_subnet_matches = re.search(IP_SUBNET_PATTERN,ip_addr)
    if ip_matches or ip_subnet_matches:
        return True
    else:
        return False
##############################################################################


# Validate Target Mac Address
##############################################################################
def validate_mac_addr(mac_addr):
    matches = re.search(MAC_PATTRN,mac_addr)
    if matches:
        return True
    else:
        return False
##############################################################################