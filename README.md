# Pcap packet layer modification tool
## HOW TO
```
> python modify_layers.py -h
usage: modify_layers.py [-h] [-i PCAP] [-j] [-d] [-l (START,END)] [-e] [-6] [-4] [-f]

A script for modifying PCAP files.

options:
  -h, --help            show this help message and exit
  -i PCAP, --input PCAP
                        Input pcap file.
  -j, --rmjnprlayer     Remove the Juniper Ethernet layer, located 12 bytes from the beginning of the packet.
  -d, --dot1q           Remove the VLAN 802.1Q layer.
  -l (START,END), --rmlayer (START,END)
                        Remove layers/bytes using start and end offsets
  -e, --addeth          Add an Ethernet layer and utilize random MAC addresses.
  -6, --toipv6          Converting the IPv4 pcap to IPv6. Utilize random IPv6 addresses.
  -4, --toipv4          Converting the IPv6 pcap to IPv4. Utilize random IPv4 addresses.
  -f, --fixchksum       Explicitly fix the checksum of the pcap. Implicitly, this fix applies to all other
                        features/arguments.
>
```
## Usage Examples
### [Example 1]: Removing VLAN 801.1Q layer
```
> python modify_layers.py -i 802.1q.vlans.pcap -d
```
#### Input pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/88780abe-6fcc-49db-9c81-09890533b7d9)
#### Output pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/9ee09a6f-27a4-4968-9cdc-5a0f358fef1b)
### [Example 2]: Removing Juniper Ethernet layer
```
> python modify_layers.py -i jnpr-ethernet-layer.pcap -j
```
#### Input pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/f874a2c1-7fcf-469f-a1fe-dca87501759a)
#### Output pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/d64b89b8-2ed8-45b1-878e-b210d7c0ddd1)
### [Example 3]: Removing Juniper Ethernet layer and VLAN 801.1Q layers together
```
> python modify_layers.py -i jnpr-ethernet-layer.pcap -j -d
```
#### Input pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/a984eb4e-f978-4bbf-a4ce-a2223ea9dc8b)
#### Output pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/aae4d179-bccb-4192-9301-5ff19042b320)
### [Example 4]: Removing layer based on offsets (Removing Juniper Ethernet layer using offsets)
```
> python modify_layers.py -i jnpr-ethernet-layer.pcap -l "(0,12)"
```
#### Input pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/c67359d3-8889-46de-b904-1be0d310a410)
#### Output pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/2ee34227-0b59-42a0-86f5-9b657362ba5d)
### [Example 5]: Add an Ethernet layer and utilize random MAC addresses
```
> python modify_layers.py -i .\unittest_cases\no_ethernet.pcap -e
```
#### Input pcap: no_ethernet.pcap
- By default, Wireshark will attempt to decode it as Ethernet, which is why you're seeing Ethernet at that layer, but it is invalid.
![no-ethernet](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/08704ca2-0024-4910-a7bf-7343b0d348f6)
#### Output pcap: modified_no_ethernet.pcap (PCAP with a valid Ethernet layer added)
![added_ethernet](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/87bab0aa-b4a7-485f-8f69-1bcd59a65e57)
### [Example 6]: Converting the IPv4 pcap to IPv6. Utilize random IPv6 addresses
```
> python modify_layers.py -i .\unittest_cases\valid_ipv4_http.pcap -6
```
#### Input pcap: valid_ipv4_http.pcap
![valid_ipv4_http](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/333d3ba9-63dd-4267-beeb-19711ec5ad7e)
#### Output pcap: modified_valid_ipv4_http.pcap (IPv6)
![modified_valid_ipv4_http](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/a2e08c0c-6144-4269-8a37-2f442aab559d)
### [Example 7]: Converting the IPv6 pcap to IPv4. Utilize random IPv4 addresses
```
> python modify_layers.py -i .\unittest_cases\valid_ipv6_http.pcap -4
```
#### Input pcap: valid_ipv6_http.pcap
![valid_ipv6_http](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/4a545d4d-cf84-43dc-b615-2495e8b6264d)
#### Output pcap: modified_valid_ipv6_http.pcap (IPv4)
![modified_valid_ipv6_http](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/6974cd6b-b2a4-4ae7-ab4b-23c73eb26c67)
### [Example 8]: Explicitly fix the checksum of the pcap. Implicitly, this fix applies to all other features/arguments.
```
> python modify_layers.py -i .\unittest_cases\invalid_tcp_chksum.pcap -f
```
#### Input pcap: invalid_tcp_chksum.pcap
![invalid_tcp_chksum](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/7e691ea7-4a98-40dd-aec4-c21c76da9070)
#### Output pcap: modified_invalid_tcp_chksum.pcap (valid TCP chksum)
![modified_invalid_tcp_chksum](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/0c2324c6-6e76-4b95-b678-bfd86558adad)
## Tested Env
- Windows 11
- Python 3.12
- Visual Studio Code 1.84
