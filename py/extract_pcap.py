#!/usr/bin/env python3
"""
extract_pcap.py - FR-7: Extract network sessions from a pcap file.
Usage: python3 py/extract_pcap.py --pcap <file> --out data/network_data.csv

Requires: scapy (pip install scapy)
Output CSV is compatible with the C++ analyzer.
"""

import argparse
import csv
import sys
from collections import defaultdict

def extract_pcap(pcap_file, out_file):
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    except ImportError:
        print("[ERROR] Scapy not installed. Run: pip install scapy", file=sys.stderr)
        sys.exit(3)

    print(f"Reading pcap: {pcap_file}")
    packets = rdpcap(pcap_file)

    # Session key: (src_ip, dst_ip, proto, src_port, dst_port)
    sessions = defaultdict(lambda: {
        'data_size': 0,
        'first_time': None,
        'last_time': None,
        'src_port': 0,
        'dst_port': 0,
        'protocol': 0,
    })

    count = 0
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        proto = ip.proto
        src_ip = ip.src
        dst_ip = ip.dst
        src_port, dst_port = 0, 0

        if proto == 6 and pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif proto == 17 and pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        key = (src_ip, dst_ip, proto, src_port, dst_port)
        s = sessions[key]
        s['data_size'] += len(pkt)
        s['protocol'] = proto
        s['src_port'] = src_port
        s['dst_port'] = dst_port
        t = float(pkt.time)
        if s['first_time'] is None or t < s['first_time']:
            s['first_time'] = t
        if s['last_time'] is None or t > s['last_time']:
            s['last_time'] = t
        count += 1

    print(f"Processed {count} packets, found {len(sessions)} sessions")

    with open(out_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Source', 'Destination', 'Protocol',
                         'SrcPort', 'DstPort', 'DataSize', 'Duration'])
        for (src_ip, dst_ip, proto, sp, dp), s in sessions.items():
            duration = 0.0
            if s['first_time'] is not None and s['last_time'] is not None:
                duration = s['last_time'] - s['first_time']
            src_port_str = str(sp) if proto in (6, 17) else ''
            dst_port_str = str(dp) if proto in (6, 17) else ''
            writer.writerow([src_ip, dst_ip, proto,
                             src_port_str, dst_port_str,
                             s['data_size'], f"{duration:.3f}"])

    print(f"Saved to {out_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract sessions from pcap file')
    parser.add_argument('--pcap', required=True, help='Input pcap file')
    parser.add_argument('--out', default='data/network_data.csv', help='Output CSV file')
    args = parser.parse_args()
    extract_pcap(args.pcap, args.out)
