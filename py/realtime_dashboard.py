import os, time, subprocess, sys
import csv

def fast_convert(pcap_path, csv_path):
    try:
        from scapy.utils import RawPcapReader
    except ImportError:
        print("[!] 请先安装 scapy: pip install scapy")
        sys.exit(1)
        
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        f.write("source,destination,protocol,src_port,dst_port,duration,data_size\n")
        writer = csv.writer(f)
        
        try:
            # 使用 RawPcapReader 是为了极速读取（比 rdpcap 快百倍），适合实时刷新的应用场景
            reader = RawPcapReader(pcap_path)
            for pkt_data in reader:
                raw_bytes, pkt_metadata = pkt_data
                # Ethernet frame 长度一般来说必须要大于 34 才包含 IPv4 头
                if len(raw_bytes) > 34:
                    eth_type = (raw_bytes[12] << 8) | raw_bytes[13]
                    if eth_type == 0x0800: # IPv4
                        ip_header = raw_bytes[14:]
                        src_ip = f"{ip_header[12]}.{ip_header[13]}.{ip_header[14]}.{ip_header[15]}"
                        dst_ip = f"{ip_header[16]}.{ip_header[17]}.{ip_header[18]}.{ip_header[19]}"
                        protocol = ip_header[9]
                        data_size = len(raw_bytes)
                        
                        src_port, dst_port = 0, 0
                        ihl = (ip_header[0] & 0x0F) * 4
                        if protocol == 6 and len(ip_header) >= ihl + 4: # TCP
                            tcp_header = ip_header[ihl:]
                            src_port = (tcp_header[0] << 8) | tcp_header[1]
                            dst_port = (tcp_header[2] << 8) | tcp_header[3]
                        elif protocol == 17 and len(ip_header) >= ihl + 4: # UDP
                            udp_header = ip_header[ihl:]
                            src_port = (udp_header[0] << 8) | udp_header[1]
                            dst_port = (udp_header[2] << 8) | udp_header[3]
                            
                        # 由于抓包文件不带持续时间聚合，默认 0.001 秒短连接
                        writer.writerow([src_ip, dst_ip, protocol, src_port, dst_port, 0.001, data_size])
        except Exception as e:
            # EOFError 等可忽略，因为 tcpdump 还在持续写入
            pass

def main():
    if len(sys.argv) < 2:
        print("用法 (Usage): python py/realtime_dashboard.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    csv_file = "data/live_data.csv"
    interval = 5   # 每 5 秒刷新一次仪表盘
    last_size = 0
    
    # 确保 C++ 核心已经编译
    if not os.path.exists("./app"):
        print("[-] C++ 后端未编译，正在自动编译中...")
        os.system("make")
    
    print("\n" + "="*50)
    print(" 🚀 实战演练：全链路实时网络态势感知系统启动")
    print("="*50 + "\n")
    
    while True:
        try:
            if not os.path.exists(pcap_file):
                print(f"[!] 正在等待 {pcap_file} 文件的产生...")
                time.sleep(1)
                continue
                
            current_size = os.path.getsize(pcap_file)
            
            # 只有抓包文件体积膨胀，意味着发生了新的网络交互，系统才进行重演分析
            if current_size > last_size:
                # 把抓包快速刷入系统所需的 CSV
                fast_convert(pcap_file, csv_file)
                last_size = current_size
                
                # 仪表盘清屏，营造复古大屏感
                os.system('clear' if os.name == 'posix' else 'cls')
                print("="*70)
                print(f" 🟢 LIVE MONITOR | 真实物理网卡 实时态势感知层")
                print(f" 📡 监听源流: {pcap_file}")
                print(f" ⏱  刷新频率: {interval}秒   |   数据包文件大小: {current_size / 1024:.2f} KB")
                print("="*70)
                
                # 调用我们的高效 C++ 分析引擎：异常抓取
                print("\n🚨 [安全预警] 异常高频单向发包节点 (疑似扫描器/僵尸网络):")
                subprocess.run(["./app", "--input", csv_file, "sort-oneway", "--threshold", "0.8", "--top", "3"])
                
                # 调用高效 C++ 分析引擎：流量统计
                print("\n📊 [带宽枢纽] 全网最新实时通信流量 Top 5 主机:")
                subprocess.run(["./app", "--input", csv_file, "sort", "--top", "5"])
                
                print(f"\n[💡] 正在收集下一波洪峰... (按 Ctrl+C 随时可以安全退出)")
                
            time.sleep(interval)
            
        except KeyboardInterrupt:
            print("\n\n[!] 已优雅退出实时监控模式。")
            break

if __name__ == '__main__':
    main()
