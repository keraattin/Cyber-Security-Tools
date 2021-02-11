#!/usr/bin/env python3


# Imports
##############################################################################
import subprocess
import argparse
##############################################################################


# Functions
##############################################################################
def change_mac_addr(iface,new_mac):
    # Down Interface
    subprocess.call(['ifconfig','{}'.format(iface),'down'])

    # Change Hw Adress
    subprocess.call(['ifconfig',
                    '{}'.format(iface),
                    'hw',
                    'ether',
                    '{}'.format(new_mac)])
    
    # Up Interface
    subprocess.call(['ifconfig','{}'.format(iface),'up'])
##############################################################################


# Main
##############################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i',
                        '--interface', 
                        dest = 'iface', 
                        help = 'Interface')
    parser.add_argument('-m',
                        '--mac', 
                        dest = 'new_mac', 
                        help = 'New MAC Address')
    args = parser.parse_args()

    change_mac_addr(args.iface,args.new_mac)

    print("[+] Your MAC Address Changed To : {}\n".format(args.new_mac))
##############################################################################