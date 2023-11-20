# Pcap packet layer modification tool
## HOW TO
```
> python3 modify_layers.py -h
usage: modify_layers.py [-h] [-i PCAP] [-j] [-d] [-l (START,END)]

Script to modify PCAP files.

options:
  -h, --help            show this help message and exit
  -i PCAP, --input PCAP
                        Input pcap file.
  -j, --rmjnprlayer     Remove Juniper Ethernet layer. Expecting it is 12 bytes from the beginning of the pkt.
  -d, --dot1q           Remove VLAN 801.1Q layer.
  -l (START,END), --rmlayer (START,END)
                        remove layers based on start & end offsets. \
                        Make sure selected layer not having dependency with its adjucent layers.
```
## Usage Examples
### [Example 1]: Removing VLAN 801.1Q layer
```
> python3 modify_layers.py -i 802.1q.vlans.pcap -d
```
#### Input pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/88780abe-6fcc-49db-9c81-09890533b7d9)
#### Output pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/9ee09a6f-27a4-4968-9cdc-5a0f358fef1b)

### [Example 2]: Removing Juniper Ethernet layer
```
> python3 modify_layers.py -i jnpr-ethernet-layer.pcap -j
```
#### Input pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/f874a2c1-7fcf-469f-a1fe-dca87501759a)
#### Output pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/d64b89b8-2ed8-45b1-878e-b210d7c0ddd1)

### [Example 3]: Removing Juniper Ethernet layer and VLAN 801.1Q layers together
```
> python3 modify_layers.py -i jnpr-ethernet-layer.pcap -j -d
```
#### Input pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/a984eb4e-f978-4bbf-a4ce-a2223ea9dc8b)
#### Output pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/aae4d179-bccb-4192-9301-5ff19042b320)

### [Example 4]: Removing layer based on offsets
```
> python3 modify_layers.py -i jnpr-ethernet-layer.pcap -l "(0,12)"
```
#### Input pcap:
![image](https://github.com/x00itachi/modify-pcap-pkt-layers/assets/2780355/c67359d3-8889-46de-b904-1be0d310a410)
#### Output pcap:

