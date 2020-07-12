#!/usr/bin/python3
# tunx.py
# version a2


from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
import sys
import argparse
from pathlib import Path


def find_ip_layer(tunnel_packet: scapy.layers.l2.Ether):
    """
    Locate tunneled protocol layer offset in provided packet capture.

    Args:
        tunnel_packet (scapy.layers.l2.Ether): the PDU to search

    Returns:
        offset (int): the byte offset of the tunneled protocol in data field of 'packet'

    """
    offset = 0
    while True:
        data = tunnel_packet[Raw].load[offset:]
        if len(data) < 20:
            offset = -1
            break
        chksum1 = tunnel_packet[Raw].load[offset + 10:offset + 12]
        chksum1 = int.from_bytes(chksum1, "big")

        temp_packet = IP()
        temp_packet[IP].chksum = None
        temp_packet = IP(data)
        # try:
        #temp_packet = Ether(dst=tunnel_packet[Ether].dst, src=tunnel_packet[Ether].src, type=tunnel_packet[Ether].type) / IP(data)
        # except:
        # print("Struct error handled")
        del temp_packet[IP].chksum
        temp_packet = temp_packet.__class__(bytes(temp_packet))
        chksum2 = temp_packet[IP].chksum
        if offset >= len(data):
            offset = -1
            break
        if chksum1 == chksum2:
            break
        offset += 1
    return offset


def find_tcp_layer(tunnel_packet: scapy.layers.l2.Ether):
    """
    Locate tunneled protocol layer offset in provided packet capture.

    Args:
        tunnel_packet (scapy.layers.l2.Ether): the PDU to search

    Returns:
        offset (int): the byte offset of the tunneled protocol in data field of 'packet'

    """
    offset = 0
    while True:
        data = tunnel_packet[Raw].load[offset:]
        if len(data) < 20:
            offset = -1
            break
        chksum1 = tunnel_packet[Raw].load[offset + 16:offset + 18]
        chksum1 = int.from_bytes(chksum1, "big")

        temp_packet = Ether() / IP() / TCP()
        temp_packet[TCP].chksum = None
        temp_packet = TCP(data)
        # try:
        # temp_packet = Ether(dst=tunnel_packet[Ether].dst, src=tunnel_packet[Ether].src, type=tunnel_packet[Ether].type)/IP(data)
        # except:
        # print("Struct error handled")
        del temp_packet[TCP].chksum
        temp_packet = temp_packet.__class__(bytes(temp_packet))
        chksum2 = temp_packet[TCP].chksum
        if offset >= len(data):
            offset = -1
            break
        if chksum1 == chksum2:
            break
        offset += 1
    return offset


def extract_tunneled_layer(tunnel_packet: scapy.layers.l2.Ether, offset: int, protocol: str, reconstruct: bool):
    """
    Extract tunneled layer from packet capture.

    Args:
        tunnel_packet (scapy.layers.l2.Ether): the PDU to extract from
        offset (int): the byte offset of the tunneled protocol in data field of 'packet'
        protocol (str): the tunneled protocol to search for
        reconstruct (bool): Attempt to reconstruct the entire PDU from encapsulating layers

    Returns:
        extracted_packet (scapy.layers.l2.Ether):

    """
    data = tunnel_packet[Raw].load[offset:]

    if not reconstruct:
        if protocol == "IP":
            extracted_packet = IP(data)
        elif protocol == "TCP":
            extracted_packet = TCP(data)
    elif protocol == "IP":
        extracted_packet = Ether(dst=tunnel_packet[Ether].dst, src=tunnel_packet[Ether].src,
                                 type=tunnel_packet[Ether].type) / IP(data)
    elif protocol == "TCP":
        extracted_packet = Ether(dst=tunnel_packet[Ether].dst, src=tunnel_packet[Ether].src,
                                 type=tunnel_packet[Ether].type) / TCP(data)
    else:
        print("Invalid protocol specified.")
        sys.exit(0)

    return extracted_packet


# initialize variables
capture_path = Path('')
packets = []

# parse arguments
parser = argparse.ArgumentParser(prog='icmptunx',
                                 description='ICMP tunnel extract.  Extract specified TCP/IP layer from ICMP tunnel.')
parser.add_argument('-o', '--offset', type=int, default=-1, help='(Optional) Offset in bytes for tunneled protocol.')
parser.add_argument('-p', '--protocol', type=str, default='IP', help='(Optional) Tunneled protocol to search for.')
parser.add_argument('-r', '--reconstruct', action="store_true",
                    help='Attempt to reconstruct full PDU using encapsulating layers.')
parser.add_argument('infile', type=Path, help='The input packet capture.')
parser.add_argument('outfile', help='The file to output extracted tcp stream to.')
args = parser.parse_args()

if not args.infile.is_file():
    print("icmptunx: error: Invalid path for capture file.")
    sys.exit(0)

# determine protocol layer to search for
if args.protocol == "IP":
    find_tunneled_layer = find_ip_layer
elif args.protocol == "TCP":
    find_tunneled_layer = find_tcp_layer
else:
    print("Invalid protocol specified.")
    sys.exit(0)

# extract tunneled layer from input file
for sniffed_packet in sniff(offline=str(args.infile), filter="icmp"):
    current_offset = args.offset
    if current_offset == -1:
        current_offset = find_tunneled_layer(sniffed_packet)
    if current_offset != -1:
        xtracted_packet = extract_tunneled_layer(sniffed_packet, current_offset, args.protocol, args.reconstruct)
        packets.append(xtracted_packet)
wrpcap(args.outfile, packets)