from scapy.layers.inet import TCP, IP, ICMP
# ARP
from scapy.layers.dns import DNS
from scapy.all import Raw


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


def malware_communication(pkt):
    """Check if the packet is part of a known malware communication."""
    return pkt.haslayer(TCP) and pkt[TCP].dport in [6667, 6697] and "PRIVMSG" in pkt[TCP].payload.decode()


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
    """Check if the packet is part of a Slowloris-like attack."""
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP) or not pkt.haslayer(Raw):
        return False
    tcp = pkt[TCP]
    ip = pkt[IP]
    raw = pkt[Raw]

    # Check if the destination port is 80 (HTTP)
    is_http = tcp.dport == 80

    # Check if the packet has a small payload
    small_payload = len(raw.load) < 20

    # Check if the packet has the SYN flag set
    syn_flag = tcp.flags == 'A'

    # Check if the IP identification field is set to 0 (default in Hping3)
    ip_id_zero = ip.id == 0
    print('in work')
    return is_http and small_payload and syn_flag and ip_id_zero


def nmap_port_scan(pkt):
    """Check if the packet is part of if Nmap port scan."""
    return pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw) and b"Nmap" in pkt[Raw].load


# List of rules
rules = [
    {"name": "SQL injection attempt", "condition": sql_injection_attempt},
    {"name": "SSH brute force attack", "condition": ssh_brute_force_attack},
    {"name": "DNS zone transfer attempt", "condition": dns_zone_transfer_attempt},
    {"name": "ICMP flood attack", "condition": icmp_flood_attack},
    {"name": "Malware communication attempt", "condition": malware_communication},
    # {"name": "ARP spoofing attempt", "condition": arp_spoofing_attempt},
    {"name": "DNS tunneling attempt", "condition": dns_tunneling_attempt},
    {"name": "Slowloris attack attempt", "condition": slowloris_attack},
    {"name": "Nmap Port scanning attempt", "condition": nmap_port_scan},
    {
        "name": "Slowloris-like Attack",
        "condition": slowloris_attack
    }

]
