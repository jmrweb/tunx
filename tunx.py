#!/usr/bin/python3
# tunx.py


from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
import sys
import argparse
from pathlib import Path


def find_tunneled_layer(tunnel_packet: scapy.layers.l2.Ether, protocol: str):
    """
    Locate tunneled protocol layer in packet capture.

    Args:
        tunnel_packet (scapy.layers.l2.Ether): the PDU to search
        protocol (str): the tunneled protocol to search for

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

        temp_packet = Ether() / IP()
        temp_packet[IP].chksum = None
        # try:
        temp_packet = Ether(dst=tunnel_packet[Ether].dst, src=tunnel_packet[Ether].src, type=tunnel_packet[Ether].type)/IP(data)
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


def extract_tunneled_layer(tunnel_packet: scapy.layers.l2.Ether, offset: int, protocol: str):
    """
    Extract tunneled layer from packet capture.

    Args:
        tunnel_packet (scapy.layers.l2.Ether): the PDU to extract from
        offset (int): the byte offset of the tunneled protocol in data field of 'packet')
        protocol (str): the tunneled protocol to search for

    Returns:
        extracted_packet (scapy.layers.l2.Ether):

    """
    data = tunnel_packet[Raw].load[offset:]
    extracted_packet = Ether(dst=tunnel_packet[Ether].dst, src=tunnel_packet[Ether].src, type=tunnel_packet[Ether].type) / IP(data)
    return extracted_packet


# initialize variables
capture_path = Path('')
packets = []

# parse arguments
parser = argparse.ArgumentParser(prog='tunx', description='Tunnel Extract.  Extract tunneled TCP/IP layers from scapy '
                                                          'compatible packet captures')
parser.add_argument('-p', '--protocol', default='IP', help='(Optional) Tunneled protocol to search for.')
parser.add_argument('-o', '--offset', type=int, default=-1, help='(Optional) Offset in bytes for tunneled protocol.')
parser.add_argument('infile', type=Path, help='The input packet capture.')
parser.add_argument('outfile', help='The file to output extracted tcp stream to.')
args = parser.parse_args()

if not args.infile.is_file():
    print("icmptunx: error: Invalid path for capture file.")
    sys.exit(0)

# MAIN: extract tcp stream from input file
for sniffed_packet in sniff(offline=str(args.infile), filter="icmp"):
    current_offset = args.offset
    if current_offset == -1:
        current_offset = find_tunneled_layer(sniffed_packet, args.protocol)
    if current_offset != -1:
        xtracted_packet = extract_tunneled_layer(sniffed_packet, current_offset, args.protocol)
        packets.append(xtracted_packet)

wrpcap(args.outfile, packets)
