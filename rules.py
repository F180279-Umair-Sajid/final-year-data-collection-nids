from scapy.layers.inet import TCP, IP, ICMP
# ARP
from scapy.layers.dns import DNS
from scapy.all import Raw


def malware_communication(pkt):
    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        if hasattr(tcp_layer.payload, "load"):
            tcp_payload = tcp_layer.payload.load.decode(errors='ignore')
            return tcp_layer.dport in [6667, 6697] and "PRIVMSG" in tcp_payload
    return False




def http_get_request(pkt):
    """Check if the packet is an HTTP GET request."""
    return pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw) and b"GET" in pkt[Raw].load


def sql_injection_attempt(pkt):
    """Check if the packet contains an SQL injection attempt."""
    return pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw) and b"SELECT" in pkt[Raw].load


def ssh_brute_force_attack(pkt):
    """Check if the packet is part of an SSH brute force attack."""
    return pkt.haslayer(TCP) and pkt[TCP].flags == "FA" and pkt[TCP].dport == 22 and pkt[IP].src != "10.0.0.1"


def dns_zone_transfer_attempt(pkt):
    """Check if the packet is a DNS zone transfer attempt."""
    return pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].opcode == 0 and len(pkt[DNS].qd) == 1 and pkt[
        DNS].qd.qtype == 252


def icmp_flood_attack(pkt):
    """Check if the packet is part of an ICMP flood attack."""
    return pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt[ICMP].code == 0 and pkt[IP].dst == "10.0.0.10"


def port_scan_attempt(pkt):
    """Check if the packet is part of a port scan."""
    return pkt.haslayer(TCP) and pkt[TCP].flags == "S" and len(pkt[TCP].payload) == 0 and pkt[IP].dst != "10.0.0.1"




arp_cache = {}


# def arp_spoofing_attempt(pkt):
#     """Check if the packet is part of an ARP spoofing attempt."""
#     if pkt.haslayer(ARP):
#         if pkt[ARP].op == 2:  # is-at
#             arp_cache[pkt[ARP].psrc] = pkt[ARP].hwsrc
#             if len(arp_cache) > 10:  # limit cache size to avoid memory issues
#                 del arp_cache[list(arp_cache.keys())[0]]
#             if arp_cache[pkt[ARP].psrc] != pkt[ARP].hwsrc:
#                 return True
#     return False


def dns_tunneling_attempt(pkt):
    """Check if the packet is part of a DNS tunneling attempt."""
    return pkt.haslayer(DNS) and len(pkt[DNS].payload) > 100


def slowloris_attack(pkt):
    """Check if the packet is part of a Slowloris attack."""
    return pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw) and len(pkt[Raw].load) < 20


def nmap_port_scan(pkt):
    """Check if the packet is part of if Nmap port scan."""
    return pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw) and b"Nmap" in pkt[Raw].load


# List of rules
rules = [
    {"name": "HTTP GET request", "condition": http_get_request},
    {"name": "SQL injection attempt", "condition": sql_injection_attempt},
    {"name": "SSH brute force attack", "condition": ssh_brute_force_attack},
    {"name": "DNS zone transfer attempt", "condition": dns_zone_transfer_attempt},
    {"name": "ICMP flood attack", "condition": icmp_flood_attack},
    {"name": "Port scanning attempt", "condition": port_scan_attempt},
    {"name": "Malware communication attempt", "condition": malware_communication},
    # {"name": "ARP spoofing attempt", "condition": arp_spoofing_attempt},
    {"name": "DNS tunneling attempt", "condition": dns_tunneling_attempt},
    {"name": "Slowloris attack attempt", "condition": slowloris_attack},
    {"name": "Nmap Port scanning attempt", "condition": nmap_port_scan},

]
