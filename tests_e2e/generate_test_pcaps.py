import os
import sys
import struct
import socket
import time

# --- PURE PYTHON GENERATOR IMPLEMENTATION (FALLBACK) ---

class PCAPBuilder:
    def __init__(self, filename):
        self.filename = filename
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        self.file = open(filename, "wb")
        # Global Header: magic (0xa1b2c3d4), major (2), minor (4), thiszone (0), sigfigs (0), snaplen (65535), network (1: Ethernet)
        global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(global_header)

    def write_packet(self, data, ts_sec=None, ts_usec=None):
        if ts_sec is None:
            t = time.time()
            ts_sec = int(t)
            ts_usec = int((t - ts_sec) * 1000000)
        incl_len = len(data)
        orig_len = len(data)
        pkt_header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        self.file.write(pkt_header)
        self.file.write(data)

    def close(self):
        self.file.close()

def build_ethernet_header(src_mac, dst_mac, eth_type=0x0800):
    src_bytes = bytes.fromhex(src_mac.replace(':', ''))
    dst_bytes = bytes.fromhex(dst_mac.replace(':', ''))
    return dst_bytes + src_bytes + struct.pack(">H", eth_type)

def build_ipv4_header(src_ip, dst_ip, protocol, payload_len, ip_id=54321, ttl=64):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    flags_fragment = 0x4000
    checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    
    header = struct.pack(">BBHHHBBH4s4s", 
                         version_ihl, tos, total_len, ip_id, 
                         flags_fragment, ttl, protocol, checksum, 
                         src_bytes, dst_bytes)
    
    # Checksum calculation
    def calc_checksum(data):
        if len(data) % 2 == 1:
            data += b'\x00'
        s = sum(struct.unpack(f">{len(data)//2}H", data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return (~s) & 0xffff

    checksum = calc_checksum(header)
    return struct.pack(">BBHHHBBH4s4s", 
                       version_ihl, tos, total_len, ip_id, 
                       flags_fragment, ttl, protocol, checksum, 
                       src_bytes, dst_bytes)

def build_tcp_header(src_port, dst_port, seq, ack, flags, window=64240):
    data_offset_reserved = 0x50  # 20 bytes
    checksum = 0
    urg_ptr = 0
    return struct.pack(">HHIIBBHHH", 
                       src_port, dst_port, seq, ack, 
                       data_offset_reserved, flags, window, 
                       checksum, urg_ptr)

def build_udp_header(src_port, dst_port, payload_len):
    return struct.pack(">HHHH", src_port, dst_port, 8 + payload_len, 0)

def build_dns_query(domain):
    dns_header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    dns_question = b""
    for part in domain.split('.'):
        dns_question += struct.pack("B", len(part)) + part.encode('ascii')
    dns_question += b"\x00"
    dns_question += struct.pack(">HH", 1, 1)  # Type A, Class IN
    return dns_header + dns_question

def generate_mock_pcap_pure(filepath):
    builder = PCAPBuilder(filepath)
    t_start = int(time.time()) - 100

    client_mac, gw_mac, attacker_mac = "00:11:22:33:44:55", "00:11:22:33:44:01", "aa:bb:cc:dd:ee:ff"
    client_ip, gw_ip, attacker_ip, google_ip = "192.168.1.50", "192.168.1.1", "10.0.0.99", "142.250.190.46"

    # 1. ARP Request & Reply
    arp_req_payload = struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, 
                                  bytes.fromhex(client_mac.replace(':', '')), socket.inet_aton(client_ip),
                                  b'\x00'*6, socket.inet_aton(gw_ip))
    builder.write_packet(build_ethernet_header(client_mac, "ff:ff:ff:ff:ff:ff", 0x0806) + arp_req_payload, t_start, 0)

    arp_rep_payload = struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, 
                                  bytes.fromhex(gw_mac.replace(':', '')), socket.inet_aton(gw_ip),
                                  bytes.fromhex(client_mac.replace(':', '')), socket.inet_aton(client_ip))
    builder.write_packet(build_ethernet_header(gw_mac, client_mac, 0x0806) + arp_rep_payload, t_start + 1, 0)

    # 2. DNS query for google.com
    dns_data = build_dns_query("google.com")
    udp_hdr = build_udp_header(53535, 53, len(dns_data))
    ip_hdr = build_ipv4_header(client_ip, gw_ip, 17, len(udp_hdr) + len(dns_data), ip_id=100)
    builder.write_packet(build_ethernet_header(client_mac, gw_mac, 0x0800) + ip_hdr + udp_hdr + dns_data, t_start + 2, 0)

    # 3. HTTP handshake to google.com
    sport = 54321
    # SYN
    tcp_hdr = build_tcp_header(sport, 80, 1000, 0, 0x02)
    ip_hdr = build_ipv4_header(client_ip, google_ip, 6, len(tcp_hdr), ip_id=200)
    builder.write_packet(build_ethernet_header(client_mac, gw_mac, 0x0800) + ip_hdr + tcp_hdr, t_start + 3, 0)
    # SYN-ACK
    tcp_hdr = build_tcp_header(80, sport, 2000, 1001, 0x12)
    ip_hdr = build_ipv4_header(google_ip, client_ip, 6, len(tcp_hdr), ip_id=201)
    builder.write_packet(build_ethernet_header(gw_mac, client_mac, 0x0800) + ip_hdr + tcp_hdr, t_start + 3, 50000)
    # ACK
    tcp_hdr = build_tcp_header(sport, 80, 1001, 2001, 0x10)
    ip_hdr = build_ipv4_header(client_ip, google_ip, 6, len(tcp_hdr), ip_id=202)
    builder.write_packet(build_ethernet_header(client_mac, gw_mac, 0x0800) + ip_hdr + tcp_hdr, t_start + 3, 60000)
    # HTTP GET payload
    http_payload = b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"
    tcp_hdr = build_tcp_header(sport, 80, 1001, 2001, 0x18)
    ip_hdr = build_ipv4_header(client_ip, google_ip, 6, len(tcp_hdr) + len(http_payload), ip_id=203)
    builder.write_packet(build_ethernet_header(client_mac, gw_mac, 0x0800) + ip_hdr + tcp_hdr + http_payload, t_start + 4, 0)

    # 4. Port Scan Anomaly (10 TCP SYNs)
    ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389]
    for idx, port in enumerate(ports):
        tcp_hdr = build_tcp_header(30000 + idx, port, 5000 + idx, 0, 0x02)
        ip_hdr = build_ipv4_header(attacker_ip, client_ip, 6, len(tcp_hdr), ip_id=1000 + idx)
        builder.write_packet(build_ethernet_header(attacker_mac, client_mac, 0x0800) + ip_hdr + tcp_hdr, t_start + 10, idx * 100000)

    # 5. Suspicious DNS query Anomaly (query malicious domain)
    dns_data = build_dns_query("malicious-c2-domain.com")
    udp_hdr = build_udp_header(53536, 53, len(dns_data))
    ip_hdr = build_ipv4_header(client_ip, gw_ip, 17, len(udp_hdr) + len(dns_data), ip_id=500)
    builder.write_packet(build_ethernet_header(client_mac, gw_mac, 0x0800) + ip_hdr + udp_hdr + dns_data, t_start + 15, 0)

    builder.close()


# --- SCAPY GENERATOR IMPLEMENTATION ---

def generate_mock_pcap_scapy(filepath):
    from scapy.all import Ether, ARP, IP, TCP, UDP, wrpcap
    try:
        from scapy.layers.dns import DNS, DNSQR
    except ImportError:
        from scapy.all import DNS, DNSQR

    packets = []
    
    # 1. ARP Request/Reply (Normal)
    packets.append(Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")/ARP(op=1, psrc="192.168.1.50", pdst="192.168.1.1"))
    packets.append(Ether(dst="00:11:22:33:44:55", src="00:11:22:33:44:01")/ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.50"))

    # 2. DNS query for google.com (Normal)
    packets.append(Ether(dst="00:11:22:33:44:01", src="00:11:22:33:44:55")/IP(src="192.168.1.50", dst="192.168.1.1")/UDP(sport=53535, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")))

    # 3. HTTP handshake to google.com (Normal)
    sport = 54321
    syn = Ether(dst="00:11:22:33:44:01", src="00:11:22:33:44:55")/IP(src="192.168.1.50", dst="142.250.190.46")/TCP(sport=sport, dport=80, flags="S", seq=1000)
    syn_ack = Ether(dst="00:11:22:33:44:55", src="00:11:22:33:44:01")/IP(src="142.250.190.46", dst="192.168.1.50")/TCP(sport=80, dport=sport, flags="SA", seq=2000, ack=1001)
    ack = Ether(dst="00:11:22:33:44:01", src="00:11:22:33:44:55")/IP(src="192.168.1.50", dst="142.250.190.46")/TCP(sport=sport, dport=80, flags="A", seq=1001, ack=2001)
    http_data = Ether(dst="00:11:22:33:44:01", src="00:11:22:33:44:55")/IP(src="192.168.1.50", dst="142.250.190.46")/TCP(sport=sport, dport=80, flags="PA", seq=1001, ack=2001)/"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"
    packets.extend([syn, syn_ack, ack, http_data])

    # 4. Port Scan (Anomaly)
    attacker_ip = "10.0.0.99"
    attacker_mac = "aa:bb:cc:dd:ee:ff"
    victim_ip = "192.168.1.50"
    victim_mac = "00:11:22:33:44:55"
    scan_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389]
    for idx, port in enumerate(scan_ports):
        scan_syn = Ether(dst=victim_mac, src=attacker_mac)/IP(src=attacker_ip, dst=victim_ip)/TCP(sport=30000 + idx, dport=port, flags="S", seq=5000 + idx)
        packets.append(scan_syn)

    # 5. Suspicious DNS query (Anomaly)
    packets.append(Ether(dst="00:11:22:33:44:01", src="00:11:22:33:44:55")/IP(src="192.168.1.50", dst="192.168.1.1")/UDP(sport=53536, dport=53)/DNS(rd=1, qd=DNSQR(qname="malicious-c2-domain.com")))

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    wrpcap(filepath, packets)


# --- MAIN HYBRID ENTRYPOINT ---

def main():
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        # Default path relative to this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(script_dir, "test_data", "mock_traffic.pcap")

    print(f"Generating mock traffic PCAP at: {filepath}")
    
    # Try importing scapy
    try:
        import scapy
        scapy_available = True
    except ImportError:
        scapy_available = False

    if scapy_available:
        print("Scapy is available. Generating PCAP using Scapy layer builder.")
        try:
            generate_mock_pcap_scapy(filepath)
            print("Successfully generated PCAP using Scapy.")
            return
        except Exception as e:
            print(f"Scapy generation failed with error: {e}. Falling back to pure Python.")
    
    print("Generating PCAP using zero-dependency pure-Python fallback.")
    try:
        generate_mock_pcap_pure(filepath)
        print("Successfully generated PCAP using pure-Python builder.")
    except Exception as e:
        print(f"PCAP generation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
