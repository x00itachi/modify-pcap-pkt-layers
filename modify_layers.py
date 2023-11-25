#!/usr/bin/env python3

################################################################################
__author__ = "Natraj G"
__email__ = "natraj.rg@gmail.com"
# Note: This tool was designed with a single session in mind. 
#       In the future, it will be improved to accommodate multi-session-based PCAPs. 
#################################################################################

import argparse
from lib_natrajPcapUtil import natrajPcapUtil

def main():
    sigutil = natrajPcapUtil()

    parser = argparse.ArgumentParser(description="A script for modifying PCAP files.")
    parser.add_argument("-i", "--input", 
                        dest='input', 
                        metavar='PCAP', 
                        help='Input pcap file.'
                        )
    parser.add_argument("-j", "--rmjnprlayer", 
                        action='store_true', 
                        help='Remove the Juniper Ethernet layer, located 12 bytes from the beginning of the packet.'
                        )
    parser.add_argument("-d", "--dot1q", 
                        action='store_true', 
                        help='Remove the VLAN 802.1Q layer.'
                        )
    parser.add_argument("-l", "--rmlayer", 
                        dest='rmlayer', 
                        metavar='(START,END)', 
                        help='Remove layers/bytes using start and end offsets'
                        )
    parser.add_argument("-e", "--addeth",
                        action='store_true',
                        help='Add an Ethernet layer and utilize random MAC addresses.'
                        )
    parser.add_argument("-6", "--toipv6",
                        action='store_true',
                        help='Converting the IPv4 pcap to IPv6. Utilize random IPv6 addresses.'
                        )
    parser.add_argument("-4", "--toipv4",
                        action='store_true',
                        help='Converting the IPv6 pcap to IPv4. Utilize random IPv4 addresses.'
                        )
    args = parser.parse_args()

    if args.input:
        sigutil.__givenpcap__ = args.input
    if args.rmjnprlayer:
        sigutil.remove_juniper_ethernet_layer()
    if args.dot1q:
        sigutil.remove_dot1q_layer()
    if args.rmlayer:
        sigutil.__rmlayer_offsets__ = args.rmlayer
        sigutil.remove_layer()
    if args.addeth:
        sigutil.add_ethernet_layer()
    if args.toipv6:
        sigutil.ipv4_to_ipv6()
    if args.toipv4:
        sigutil.ipv6_to_ipv4()

if __name__ == "__main__":
    main()
