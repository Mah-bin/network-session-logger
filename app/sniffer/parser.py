from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import socket
import ipaddress
import subprocess

# ---------------------------------------------------------------
# parse_packet
# Takes a raw Scapy packet and returns a flat dict of session
# metadata. Returns None if the packet has no IP layer.
# ---------------------------------------------------------------
def parse_packet(packet):
    # Only process packets with an IP layer
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    parsed = {
        'src_ip':      ip_layer.src,
        'dst_ip':      ip_layer.dst,
        'src_mac':     None,
        'dst_mac':     None,
        'src_port':    None,
        'dst_port':    None,
        'protocol':    None,
        'packet_size': len(packet),
    }

    # Extract MAC addresses if Ethernet layer is present
    if packet.haslayer(Ether):
        eth = packet[Ether]
        parsed['src_mac'] = eth.src
        parsed['dst_mac'] = eth.dst

    # Extract port and protocol based on transport layer
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        parsed['src_port'] = tcp.sport
        parsed['dst_port'] = tcp.dport
        parsed['protocol'] = 'TCP'

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        parsed['src_port'] = udp.sport
        parsed['dst_port'] = udp.dport
        parsed['protocol'] = 'UDP'

    elif packet.haslayer(ICMP):
        parsed['protocol'] = 'ICMP'

    else:
        # Fallback: use IP protocol number
        parsed['protocol'] = str(ip_layer.proto)

    return parsed


# ---------------------------------------------------------------
# resolve_hostname
# Attempts a reverse DNS lookup for an IP address.
# Returns None on failure rather than crashing.
# ---------------------------------------------------------------
def resolve_hostname(ip):
    # Try reverse DNS first
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except (socket.herror, socket.gaierror, OSError):
        pass

    # Try NetBIOS (works for Windows devices)
    try:
        result = subprocess.run(
            ['nbtstat', '-A', ip],
            capture_output=True, text=True, timeout=1
        )
        for line in result.stdout.splitlines():
            if '<00>' in line and 'UNIQUE' in line:
                name = line.strip().split()[0]
                if name:
                    return name
    except Exception:
        pass

    return None


# ---------------------------------------------------------------
# get_vendor
# Looks up the NIC vendor from the first 3 octets of a MAC.
# Uses a small hardcoded table of common vendors.
# For production, replace with the full IEEE OUI database.
# ---------------------------------------------------------------
OUI_TABLE = {
    '00:50:56': 'VMware',
    '00:0c:29': 'VMware',
    '08:00:27': 'VirtualBox',
    'b8:27:eb': 'Raspberry Pi',
    'dc:a6:32': 'Raspberry Pi',
    'e4:5f:01': 'Raspberry Pi',
    '00:1a:11': 'Google',
    'f4:f5:d8': 'Google',
    'ac:de:48': 'Apple',
    '00:17:f2': 'Apple',
    'a4:c3:f0': 'Apple',
    '00:1b:63': 'Apple',
    '3c:5a:b4': 'Google Nest',
    '00:e0:4c': 'Realtek',
    '00:1d:60': 'Intel',
    '8c:8d:28': 'Intel',
    '00:26:b9': 'Dell',
    'f8:db:88': 'Dell',
    'fc:3f:db': 'Dell',
    '00:25:90': 'Super Micro',
    'ff:ff:ff': 'Broadcast',
}

def get_vendor(mac_address):
    if not mac_address:
        return None
    prefix = mac_address.lower()[:8]
    return OUI_TABLE.get(prefix, 'Unknown')

LOCAL_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
]

def is_local_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in LOCAL_RANGES)
    except ValueError:
        return False