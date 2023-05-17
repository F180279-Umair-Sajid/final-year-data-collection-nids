from scapy.all import *
from collections import defaultdict

from scapy.layers.inet import TCP, IP

# Define a dictionary to count unique destination ports per source IP
src_ip_to_dst_ports = defaultdict(set)


# Define the packet callback function
def packet_callback(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags

        # Add the destination port to the set for the source IP
        src_ip_to_dst_ports[src_ip].add(dst_port)

        # Define a threshold for the number of unique destination ports
        THRESHOLD = 100

        # Check if the count of unique destination ports exceeds a threshold
        # and if the TCP flags field is set to SYN (0x02)
        if len(src_ip_to_dst_ports[src_ip]) > THRESHOLD and tcp_flags == 'S':
            alert_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port
            }

            alert = f"Alert: Possible SYN scan detected from {src_ip}!\n{alert_info}"
            print(alert)
            # Here, you could add the code to take appropriate action based on the alert


# Sniff packets and process them
sniff(prn=packet_callback, store=0)
