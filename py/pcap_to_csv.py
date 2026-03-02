import sys
import csv
import argparse

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
except ImportError:
    print("Error: Scapy library is required.")
    print("Please install it by running: pip install scapy")
    sys.exit(1)

def convert_pcap(pcap_file, csv_file):
    print(f"[*] Reading physical network capture file: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Failed to read PCAP file: {e}")
        sys.exit(1)
        
    print(f"[*] Loaded {len(packets)} packets. Extracing session metrics...")
    
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        # Header defined by the C++ analyzer
        writer.writerow(['source', 'destination', 'protocol', 'src_port', 'dst_port', 'duration', 'data_size'])
        
        valid_records = 0
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                data_size = len(pkt)
                duration = 0.001 # Simulated minimal duration for single unmerged packet
                
                src_port = 0
                dst_port = 0
                
                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                elif ICMP in pkt:
                    pass # ICMP has no ports
                
                writer.writerow([src_ip, dst_ip, protocol, src_port, dst_port, duration, data_size])
                valid_records += 1
                
    print(f"[*] Success! Converted {valid_records} IP packets into session CSV format.")
    print(f"[*] Output saved to -> {csv_file}")
    print("[*] You can now feed this CSV into the Network Analyzer C++ backend.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Convert real PCAP capture files to Analyzer CSV format.")
    parser.add_argument("pcap_file", help="Input .pcap file path")
    parser.add_argument("csv_file", help="Output .csv file path")
    args = parser.parse_args()
    
    convert_pcap(args.pcap_file, args.csv_file)
