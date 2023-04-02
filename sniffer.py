from scapy.all import *
import datetime
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, ICMP


def sniff_and_store_wifi_postgres(db, iface, rules):
    def process_packet(packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            flow_id = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
            protocol = packet[IP].proto
            timestamp = datetime.datetime.now()
            flow_duration = packet.time
            total_fwd_packets = 1 if packet[IP].src < packet[IP].dst else 0
            total_bwd_packets = 1 if packet[IP].src > packet[IP].dst else 0
            total_fwd_packet_size = len(packet[TCP].payload) if packet[IP].src < packet[IP].dst else 0
            total_bwd_packet_size = len(packet[TCP].payload) if packet[IP].src > packet[IP].dst else 0
            total_fwd_payload_size = len(packet[TCP].payload) if packet[IP].src < packet[IP].dst else 0
            total_bwd_payload_size = len(packet[TCP].payload) if packet[IP].src > packet[IP].dst else 0

            for rule in rules:
                if rule["condition"](packet):
                    db.insert_record("alerts", ("name", "description", "timestamp"),
                                     (rule["name"], f"Packet matched rule: {rule['name']}", timestamp))

            db.insert_record("nids", (
                'flow_id', 'protocol', 'timestamp', 'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
                'total_fwd_packet_size', 'total_bwd_packet_size', 'total_fwd_payload_size', 'total_bwd_payload_size'),
                             (flow_id, protocol, timestamp, flow_duration,
                              total_fwd_packets, total_bwd_packets, total_fwd_packet_size, total_bwd_packet_size,
                              total_fwd_payload_size, total_bwd_payload_size))

    sniff(iface=iface, prn=process_packet)
