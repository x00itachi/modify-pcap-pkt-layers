# Pcap packet layer modification tool
## HOWTO
```
> python3 modify_layers.py -h
usage: modify_layers.py [-h] [-i PCAP] [-j] [-d] [-l (START,END)]

Script to modify PCAP files.

options:
  -h, --help            show this help message and exit
  -i PCAP, --input PCAP
                        Input pcap file.
  -j, --rmjnprlayer     Remove juniper ethernet layer. Expecting it is 12 bytes from the beginning of the pkt.
  -d, --dot1q           Remove VLAN 801.1Q layer.
  -l (START,END), --rmlayer (START,END)
                        remove layers based on start & end offsets. Make sure selected layer not having dependency with its adjucent layers.
```