from scapy.all import *
import datetime
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, ICMP
import requests
from requests.auth import HTTPBasicAuth
EXCLUDED_IP = "104.17.83.18"
IBM_EXCHANGE_API_KEY = "ed92b7d9-bc53-4843-a7a4-c1f45688077d"
IBM_EXCHANGE_API_PASSWORD = "a8c40fb8-a407-461d-afd1-c1465eca223c"
IBM_EXCHANGE_API_BASE_URL = "https://exchange.xforce.ibmcloud.com/api/ipr/'"  # Replace with the actual API base URL
from ipaddress import ip_address, ip_network


def is_private_ip(ip_address_str):
    private_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16","104.17.83.18"]
    ip_addr = ip_address(ip_address_str)
    for network in private_networks:
        if ip_addr in ip_network(network):
            return True
    return False


def is_ip_malicious(ip_address):
    url = f"https://exchange.xforce.ibmcloud.com/api/ipr/{ip_address}"

    # Set the header to accept JSON
    headers = {'Accept': 'application/json'}

    # Make a GET request to the IBM Exchange API with authentication
    response = requests.get(url, auth=HTTPBasicAuth(IBM_EXCHANGE_API_KEY, IBM_EXCHANGE_API_PASSWORD), headers=headers)

    # Check the API response
    if response.status_code == 200:
        try:
            data = response.json()

            # Get the most recent history item and its score
            history = data.get("history", [])
            if history:
                most_recent_history_item = history[-1]
                score = most_recent_history_item.get("score", 0)
            else:
                score = 0

            is_malicious = score > 0

            # If IP is not malicious, return None
            if not is_malicious:
                return None

            # Extract additional information about the IP
            ip_info = {
                "ip": ip_address,
                "country": data.get("geo", {}).get("country", ""),
                "country_code": data.get("geo", {}).get("countrycode", ""),
                # Extract other relevant fields as needed
            }

            # Return is_malicious and IP info only if the IP is malicious
            return ip_info
        except Exception as e:
            print(f"Error parsing JSON: {e}")
    else:
        # Print the error message if the request fails
        print(f"Error: {response.status_code}, {response.text}")

    # Return None if the request fails or the response is not as expected
    return None


def sniff_and_store_wifi_postgres(db, iface, rules):
    flows = {}

    def process_packet(packet):
        nonlocal flows

        if packet.haslayer(IP) and packet.haslayer(TCP):
            flow_id = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
            sender_ip = packet[IP].src
            timestamp = datetime.datetime.now()

            if flow_id not in flows:
                flows[flow_id] = {'timestamps': [], 'src_ips': [], 'payload_lengths': [], 'packet_lengths': []}

            flows[flow_id]['timestamps'].append(packet.time)
            flows[flow_id]['src_ips'].append(sender_ip)
            flows[flow_id]['payload_lengths'].append(len(packet[TCP].payload))
            flows[flow_id]['packet_lengths'].append(len(packet))

            # Additional code for SYN scan detection and alert record insertion
            if packet[TCP].flags == 'S':
                alert_name = "SYN Scan"
                alert_description = "SYN scan detected"
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

                db.insert_record("alerts", (
                    "timestamp", "name", "description", "src_ip", "dst_ip", "src_port", "dst_port"),
                                 (timestamp, alert_name, alert_description, src_ip, dst_ip, src_port, dst_port))

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
                    db.insert_record(
                        "alerts",
                        ("name", "description", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port"),
                        (
                            rule["name"], f"Packet matched rule: {rule['name']}", timestamp, packet[IP].src,
                            packet[IP].dst,
                            packet[TCP].sport, packet[TCP].dport)
                    )
            if sender_ip != EXCLUDED_IP and not is_private_ip(sender_ip):
                ip_info = is_ip_malicious(sender_ip)
                if ip_info is not None:  # Check if ip_info is not None
                    db.insert_ip_malicious(ip_info['ip'], True, ip_info['country'], ip_info['country_code'])
                else:
                    print(f"Unable to retrieve information for IP: {sender_ip}")

            db.insert_record("nids", (
                'flow_id', 'timestamp', 'flow_duration', 'flow_iat_mean', 'fwd_iat_tot',
                'subflow_fwd_pkts', 'subflow_fwd_bytes', 'fwd_act_data_pkts', 'fwd_seg_size_min',
                'bwd_pkts_count', 'bwd_bytes_per_avg', 'bwd_payload_count', 'bwd_payload_bytes_per_avg',
                'bwd_blk_rate_avg', 'bwd_pkts_per_avg'),
                             (flow_id, timestamp, flow_duration, flow_iat_mean, fwd_iat_tot,
                              subflow_fwd_pkts, subflow_fwd_bytes, fwd_act_data_pkts, fwd_seg_size_min,
                              bwd_pkts_count, bwd_bytes_per_avg, bwd_payload_count, bwd_payload_bytes_per_avg,
                              bwd_blk_rate_avg, bwd_pkts_per_avg))

    sniff(iface=iface, prn=process_packet)
