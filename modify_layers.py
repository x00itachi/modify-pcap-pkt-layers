#!/usr/bin/env python3
################################################################################
__author__ = "Natraj G"
__email__ = "natraj.rg@gmail.com"
# Note: This tool was developed considering a single session. 
#       In the future, it will be enhanced to support multi-session-based pcaps.
#################################################################################
import argparse
from scapy.all import *
import ast

class natrajPcapUtil(object):
    def __init__(self):
        self.__givenpcap__ = None
        self.__modifiedpkts__ = None
        self.__rmlayer_offsets__ = None
        self.__ip_mac_mapping__ = {}
        self.__ip_v4_v6_mapping__ = {}

    def _fix_chksum_(self, pkt):
        if IP in pkt:
            pkt[IP].chksum = None  # recalculate
            del pkt[IP].chksum     # delete cache
        if ICMP in pkt:
            pkt[ICMP].chksum = None
            del pkt[ICMP].chksum
        if TCP in pkt:
            pkt[TCP].chksum = None
            del pkt[TCP].chksum
        return pkt

    @staticmethod
    def modifypcap(func):
        def inner(cls_instance, pcapfile=None):
            pcapfile = pcapfile or cls_instance.__givenpcap__
            if cls_instance.__modifiedpkts__: 
                pkts = cls_instance.__modifiedpkts__
            else:
                pkts = rdpcap(pcapfile)
            newpkts = []
            for pkt in pkts:
                newpkt = func(cls_instance, pkt)
                newpkt = cls_instance._fix_chksum_(newpkt)
                newpkts.append(newpkt)
            cls_instance.__writepcap__(newpkts)
        return inner

    def __writepcap__(self, newpkts):
        self.__modifiedpkts__ = newpkts  # used while calling more than one switch.
        wrpcap('modified_%s' % self.__givenpcap__, newpkts)

    @modifypcap
    def remove_juniper_ethernet_layer(self, pkt=None):
        juniper_header_length = 12
        juniper_header_magic_bytes = b'MGC'
        if bytes(pkt).startswith(juniper_header_magic_bytes):
            newpkt = bytes(pkt)[juniper_header_length:]
        else:
            newpkt = pkt
        return newpkt
    
    @modifypcap
    def remove_dot1q_layer(self, pkt=None):
        if type(pkt) is bytes:
            pkt = Ether(pkt)
        if type(pkt) is Ether:
            if Dot1Q in pkt:
                smac = pkt[Ether].src
                dmac = pkt[Ether].dst
                newpkt = Ether(src=smac, dst=dmac)/pkt[Dot1Q].payload
            else:
                newpkt = pkt
        else:
            newpkt = pkt
        return newpkt
    
    @modifypcap
    def remove_layer(self, pkt=None):
        pkt_bytes = bytes(pkt)
        start_ofs, end_ofs = ast.literal_eval(self.__rmlayer_offsets__)
        newpkt = pkt_bytes[:start_ofs] + pkt_bytes[end_ofs:]
        return newpkt
    
    @modifypcap
    def add_ethernet_layer(self, pkt=None):
        """
        Currently created to cover only IPv4 sublayer.
        """
        pkt_bytes = bytes(pkt)
        ip_layer = IP(pkt_bytes)
        sip, dip = ip_layer[IP].src, ip_layer[IP].dst
        if len(self.__ip_mac_mapping__) == 0:
            self.__ip_mac_mapping__[sip] = str(RandMAC())
            self.__ip_mac_mapping__[dip] = str(RandMAC())
        newpkt = Ether(src=self.__ip_mac_mapping__[sip], dst=self.__ip_mac_mapping__[dip])/ip_layer
        return newpkt

    @modifypcap
    def ipv4_to_ipv6(self, pkt=None):
        sip, dip = pkt[IP].src, pkt[IP].dst
        smac, dmac = pkt[Ether].src, pkt[Ether].dst
        ip_payload = pkt[IP].payload
        if len(self.__ip_v4_v6_mapping__) == 0:
            self.__ip_v4_v6_mapping__[sip] = str(RandIP6())
            self.__ip_v4_v6_mapping__[dip] = str(RandIP6())
        if len(self.__ip_mac_mapping__) == 0:
            self.__ip_mac_mapping__[sip] = smac
            self.__ip_mac_mapping__[dip] = dmac
        newpkt = Ether(
            src=self.__ip_mac_mapping__[sip], 
            dst=self.__ip_mac_mapping__[dip]
            )/IPv6(
                src=self.__ip_v4_v6_mapping__[sip],
                dst=self.__ip_v4_v6_mapping__[dip]
                )/ip_payload
        return newpkt
    
    @modifypcap
    def ipv6_to_ipv4(self, pkt=None):
        sip6, dip6 = pkt[IPv6].src, pkt[IPv6].dst
        smac, dmac = pkt[Ether].src, pkt[Ether].dst
        ip6_payload = pkt[IPv6].payload
        if len(self.__ip_v4_v6_mapping__) == 0:
            self.__ip_v4_v6_mapping__[sip6] = str(RandIP())
            self.__ip_v4_v6_mapping__[dip6] = str(RandIP())
        if len(self.__ip_mac_mapping__) == 0:
            self.__ip_mac_mapping__[sip6] = smac
            self.__ip_mac_mapping__[dip6] = dmac
        newpkt = Ether(
            src=self.__ip_mac_mapping__[sip6], 
            dst=self.__ip_mac_mapping__[dip6]
            )/IP(
                src=self.__ip_v4_v6_mapping__[sip6],
                dst=self.__ip_v4_v6_mapping__[dip6]
                )/ip6_payload
        return newpkt

def main():
    sigutil = natrajPcapUtil()

    parser = argparse.ArgumentParser(description="Script to modify PCAP files.")
    parser.add_argument("-i", "--input", 
                        dest='input', 
                        metavar='PCAP', 
                        help='Input pcap file.'
                        )
    parser.add_argument("-j", "--rmjnprlayer", 
                        action='store_true', 
                        help='Remove juniper ethernet layer. Expecting it is 12 bytes from the beginning of the pkt.'
                        )
    parser.add_argument("-d", "--dot1q", 
                        action='store_true', 
                        help='Remove VLAN 801.1Q layer.'
                        )
    parser.add_argument("-l", "--rmlayer", 
                        dest='rmlayer', 
                        metavar='(START,END)', 
                        help='Remove layers based on start & end offsets. Make sure selected layer not having dependency with its adjucent layers.'
                        )
    parser.add_argument("-e", "--addeth",
                        action='store_true',
                        help='Add ethernet layer.'
                        )
    parser.add_argument("-6", "--toipv6",
                        action='store_true',
                        help='Changing the IPv4 pcap to IPv6.'
                        )
    parser.add_argument("-4", "--toipv4",
                        action='store_true',
                        help='Changing the IPv6 pcap to IPv4.'
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
