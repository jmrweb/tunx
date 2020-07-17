# tunx
### Name:
tunx, tunnel extractor

### Synopis:
python3 tunx [-o offset] [input_file] [output_file]

### Description:
Extracts ICMP tunneled TCP/IP layers from scapy compatible packet captures.

Looks for tunneled layer in 'data' field of ICMP packet (ICMP.data of Ether/IP/ICMP frame) and extracts to output file as pcap.

### Options:

**Required:**
- input_file    Capture file to extract from.  Works with scapy compatible capture files.
- output_file   File to write extracted layer to.
  
**Optional:**
- -o            Specify byte offset of tunneled layer in data field.

### Examples: 
python3 tunx Ping.pcap extract.pcap
python3 tunx -o 5 sneakers.pcap extract2.pcap

### Author:
James Read
