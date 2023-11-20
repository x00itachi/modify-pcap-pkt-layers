#!/usr/bin/env python3

__author__ = "Natraj G"
__email__ = "natraj.rg@gmail.com"

import argparse
from scapy.all import *
import ast

class natrajPcapUtil(object):
    def __init__(self):
        self.__givenpcap__ = None
        self.__modifiedpkts__ = None
        self.__rmlayer_offsets__ = None

    def _fix_chksum_(self, pkt):
        pkt = Ether(pkt)
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
                        help='remove layers based on start & end offsets. Make sure selected layer not having dependency with its adjucent layers.')
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

if __name__ == "__main__":
    main()
