import ast, os
from scapy.all import *

class NatrajPcapUtil:
    """Pcap Utility class."""
    def __init__(self):
        self.__givenpcap__ = None
        self.__modifiedpkts__ = None
        self.__rmlayer_offsets__ = None
        self.__ip_mac_mapping__ = {}
        self.__ip_v4_v6_mapping__ = {}

    def _fix_chksum_(self, pkt):
        """Fix packet checksum."""
        if type(pkt) is bytes:
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

    def __read_pcapfile__(self, pcapfile):
        """Read provided pcap file."""
        try:
            pkts = rdpcap(pcapfile)
        except FileNotFoundError:
            print("File not found:", pcapfile)
        return pkts

    @staticmethod
    def modifypcap(func):
        """Decorator function, used to trigger before any feature."""
        def inner(cls_instance, pcapfile=None):
            pcapfile = pcapfile or cls_instance.__givenpcap__
            if cls_instance.__modifiedpkts__:
                pkts = cls_instance.__modifiedpkts__
            else:
                pkts = cls_instance.__read_pcapfile__(pcapfile)
            newpkts = []
            for pkt in pkts:
                newpkt = func(cls_instance, pkt)
                newpkt = cls_instance._fix_chksum_(newpkt)
                newpkts.append(newpkt)
            cls_instance.__writepcap__(newpkts)
        return inner

    def __writepcap__(self, newpkts):
        """Write newpkts to new pcap."""
        self.__modifiedpkts__ = newpkts  # used while calling more than one switch.
        new_pcapname = f'modified_{os.path.basename(self.__givenpcap__)}'
        existing_pcap_dir = os.path.dirname(self.__givenpcap__)
        newfilepath = os.path.join(existing_pcap_dir, new_pcapname)
        wrpcap(newfilepath, newpkts)

    @modifypcap
    def remove_juniper_ethernet_layer(self, pkt=None):
        """(-j) Remove the Juniper Ethernet layer, 
                    located 12 bytes from the beginning of the packet."""
        juniper_header_length = 12
        juniper_header_magic_bytes = b'MGC'
        if bytes(pkt).startswith(juniper_header_magic_bytes):
            newpkt = bytes(pkt)[juniper_header_length:]
        else:
            newpkt = pkt
        return newpkt

    @modifypcap
    def remove_dot1q_layer(self, pkt=None):
        """(-d) Remove the VLAN 802.1Q layer."""
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
        """(-l (START,END)) Remove layers/bytes using start and end offsets"""
        pkt_bytes = bytes(pkt)
        start_ofs, end_ofs = ast.literal_eval(self.__rmlayer_offsets__)
        newpkt = pkt_bytes[:start_ofs] + pkt_bytes[end_ofs:]
        return newpkt

    @modifypcap
    def add_ethernet_layer(self, pkt=None):
        """
        (-e) Add an Ethernet layer and utilize random MAC addresses.
        Note: Currently created to cover only IPv4 sublayer.
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
        """(-6) Converting the IPv4 pcap to IPv6. Utilize random IPv6 addresses."""
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
        """(-4) Converting the IPv6 pcap to IPv4. Utilize random IPv4 addresses."""
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

    @modifypcap
    def fix_pcap_chksum(self, pkt=None):
        """(-f) Explicitly fix the checksum of the pcap. Implicitly, this fix applies to all other features/arguments."""
        return pkt
