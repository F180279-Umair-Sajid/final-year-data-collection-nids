from scapy.all import *
import datetime
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, ICMP
from collections import defaultdict
import time

# You might need to add additional imports, depending on the implementation of the 'db' object.
# For example, if you use the 'psycopg2' library, you would need to import it.

flows = defaultdict(lambda: defaultdict(list))


def sniff_and_store_wifi_postgres(db, iface, rules):
    def process_packet(packet):
        print(packet.summary())
        if packet.haslayer(IP) and packet.haslayer(TCP):
            flow_id = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
            sender_ip = packet[IP].src
            protocol = packet[IP].proto
            timestamp = datetime.datetime.now()

            flows[flow_id]['timestamps'].append(time.time())
            flows[flow_id]['packet_lengths'].append(len(packet))
            flows[flow_id]['payload_lengths'].append(len(packet[TCP].payload))
            flows[flow_id]['src_ips'].append(packet[IP].src)

            if sender_ip != packet[IP].src:
                flows[flow_id]['bwd_pkts_count'] += 1

            # Calculate features
            flow_duration = max(flows[flow_id]['timestamps']) - min(flows[flow_id]['timestamps'])
            flow_iat_mean = (max(flows[flow_id]['timestamps']) - min(flows[flow_id]['timestamps'])) / (
                    len(flows[flow_id]['timestamps']) - 1) if len(flows[flow_id]['timestamps']) > 1 else 0
            fwd_iat_tot = sum(t2 - t1 for t1, t2, src1, src2 in
                              zip(flows[flow_id]['timestamps'][:-1], flows[flow_id]['timestamps'][1:],
                                  flows[flow_id]['src_ips'][:-1], flows[flow_id]['src_ips'][1:]) if
                              src1 == src2 and src1 == sender_ip)

            fwd_payload_lengths = [pl for pl, src in zip(flows[flow_id]['payload_lengths'], flows[flow_id]['src_ips'])
                                   if src == sender_ip]
            subflow_fwd_pkts = len(fwd_payload_lengths)
            subflow_fwd_bytes = sum(fwd_payload_lengths)

            fwd_act_data_pkts = sum(
                1 for pl, src in zip(flows[flow_id]['payload_lengths'], flows[flow_id]['src_ips']) if
                pl > 0 and src == sender_ip)
            fwd_seg_size_min = min(fwd_payload_lengths) if fwd_payload_lengths else 0

            bwd_packet_lengths = [pl for pl, src in zip(flows[flow_id]['packet_lengths'], flows[flow_id]['src_ips']) if
                                  src != sender_ip]
            bwd_pkts_count = len(bwd_packet_lengths)
            bwd_bytes_per_avg = sum(bwd_packet_lengths) / bwd_pkts_count if bwd_pkts_count > 0 else 0

            bwd_payload_lengths = [pl for pl, src in zip(flows[flow_id]['payload_lengths'], flows[flow_id]['src_ips'])
                                   if src != sender_ip]
            bwd_payload_count = len(bwd_payload_lengths)
            bwd_payload_bytes_per_avg = sum(bwd_payload_lengths) / bwd_payload_count if bwd_payload_count > 0 else 0
            bwd_blk_rate_avg = bwd_pkts_count / flow_duration if flow_duration > 0 else 0

            bwd_packet_timestamps = [ts for ts, src in zip(flows[flow_id]['timestamps'], flows[flow_id]['src_ips']) if
                                     src != sender_ip]
            bwd_pkts_per_avg = len(bwd_packet_lengths) / len(bwd_packet_timestamps) if len(
                bwd_packet_timestamps) > 0 else 0

            for rule in rules:
                if rule["condition"](packet):
                    print('on insertion')
                    db.insert_record("alerts", ("name", "description", "timestamp"),
                                     (rule["name"], f"Packet matched rule: {rule['name']}", timestamp))

            db.insert_record("nids", (
                'flow_id', 'sender_ip', 'protocol', 'timestamp', 'flow_duration', 'fwd_iat_tot',
                'flow_iat_mean',
                'bwd_bytes_per_avg', 'bwd_pkts_per_avg', 'bwd_blk_rate_avg', 'subflow_fwd_pkts', 'subflow_fwd_bytes',
                'fwd_act_data_pkts', 'fwd_seg_size_min'),
                             (flow_id, sender_ip, protocol, timestamp, flow_duration, fwd_iat_tot, flow_iat_mean,
                              bwd_bytes_per_avg, bwd_pkts_per_avg, bwd_blk_rate_avg, subflow_fwd_pkts,
                              subflow_fwd_bytes,
                              fwd_act_data_pkts, fwd_seg_size_min))

    sniff(iface=iface, prn=process_packet)
