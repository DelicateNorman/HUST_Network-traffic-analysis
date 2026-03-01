#!/usr/bin/env python3
"""
visualize_subgraph.py - FR-9: Enhanced "Bloom" Visualization.
Usage: python3 py/visualize_subgraph.py --edges out/subgraph_edges.csv --nodes out/subgraph_edges_nodes.csv --out out/subgraph.html

Requires: networkx, pyvis (pip install networkx pyvis)
"""

import argparse
import csv
import sys
import os
import math

def visualize(edges_file, nodes_file, out_file):
    try:
        import networkx as nx
    except ImportError:
        print("[ERROR] networkx not installed. Run: pip install networkx", file=sys.stderr)
        sys.exit(3)
    try:
        from pyvis.network import Network
    except ImportError:
        print("[ERROR] pyvis not installed. Run: pip install pyvis", file=sys.stderr)
        sys.exit(3)

    G = nx.DiGraph()
    
    # 1. Load Nodes
    node_attr = {}
    if os.path.exists(nodes_file):
        with open(nodes_file, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row['ip']
                node_attr[ip] = {
                    'total_bytes': int(row['total_bytes']),
                    'out_ratio': float(row['out_ratio']),
                    'is_oneway': int(row['is_oneway']),
                    'degree': int(row['degree'])
                }
                G.add_node(ip)
    
    # 2. Load Edges
    edge_count = 0
    with open(edges_file, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            src = row['src_ip']
            dst = row['dst_ip']
            tb  = int(row['total_bytes'])
            td  = float(row['total_duration'])
            # Protocol breakdown
            tcp = int(row.get('tcp_bytes', 0))
            udp = int(row.get('udp_bytes', 0))
            icmp = int(row.get('icmp_bytes', 0))
            
            G.add_edge(src, dst, weight=tb, duration=td, 
                       tcp=tcp, udp=udp, icmp=icmp)
            edge_count += 1

    print(f"Loaded {G.number_of_nodes()} nodes, {edge_count} edges")

    # 3. Build pyvis network with premium aesthetics
    net = Network(height='900px', width='100%', directed=True,
                  bgcolor='#0f0f1b', font_color='#e0e0e0')
    
    # Fine-tuned physics for "organic" feel
    net.force_atlas_2based(
        gravity=-60,
        central_gravity=0.005,
        spring_length=150,
        spring_strength=0.08,
        damping=0.4
    )

    # 4. Add Nodes with Semantic Styling
    for node in G.nodes():
        attr = node_attr.get(node, {'total_bytes': 0, 'out_ratio': 0, 'is_oneway': 0, 'degree': 0})
        
        # Size based on traffic (log scale)
        bytes_val = attr['total_bytes']
        size = 10 + (math.log10(bytes_val + 1) * 5)
        
        # Color & Border
        # Default: Neon Cyan/Blue
        # Anomaly (Oneway): Glowing Red
        if attr['is_oneway']:
            color = {'background': '#ff0055', 'border': '#ffffff', 'highlight': '#ff4d88'}
            label_color = '#ff0055'
            border_width = 3
            shape = 'diamond'
        else:
            # Gradient based on traffic volume
            # Low: Deep Indigo (#4a00e0) to High: Neon Cyan (#00d2ff)
            ratio = min(1.0, math.log10(bytes_val + 1) / 8.0)
            r = int(74 + (0 - 74) * ratio)
            g = int(0 + (210 - 0) * ratio)
            b = int(224 + (255 - 224) * ratio)
            color = f'#{r:02x}{g:02x}{b:02x}'
            label_color = '#e0e0e0'
            border_width = 1
            shape = 'dot'

        title = (f"<b>Node: {node}</b><br>"
                 f"Total Traffic: {bytes_val:,} bytes<br>"
                 f"Outbound Ratio: {attr['out_ratio']:.1%}<br>"
                 f"Degree: {attr['degree']}<br>"
                 f"{'⚠️ ANOMALY: Highly Outbound' if attr['is_oneway'] else 'Status: Normal'}")

        net.add_node(node, label=node, title=title,
                     color=color, size=size, shape=shape,
                     borderWidth=border_width, font={'color': label_color, 'size': 14})

    # 5. Add Edges with Protocol Visuals
    for src, dst, data in G.edges(data=True):
        tb = data['weight']
        td = data['duration']
        tcp = data['tcp']
        udp = data['udp']
        icmp = data['icmp']
        
        # Width proportional to volume
        width = 1 + (math.log10(tb + 1))
        
        # Edge color highlights protocol dominance
        if tcp > udp and tcp > icmp:
            color = '#00d2ff88' # Neon Blue (TCP)
        elif udp > tcp and udp > icmp:
            color = '#ffaa0088' # Orange (UDP)
        else:
            color = '#ffffff44' # Grey
            
        title = (f"<b>Connection: {src} → {dst}</b><br>"
                 f"Volume: {tb:,} bytes<br>"
                 f"Duration: {td:.2f}s<br>"
                 f"<hr>"
                 f"TCP: {tcp:,} bytes<br>"
                 f"UDP: {udp:,} bytes<br>"
                 f"ICMP: {icmp:,} bytes")
        
        net.add_edge(src, dst, title=title, width=width, color=color, arrows='to')

    # Custom JS for "Neon Glow" effect in browser (Subtle shadow)
    net.set_options("""
    {
      "nodes": {
        "shadow": {
          "enabled": true,
          "color": "rgba(0,0,0,0.5)",
          "size": 10,
          "x": 5,
          "y": 5
        }
      },
      "edges": {
        "smooth": {
          "type": "curvedCW",
          "roundness": 0.2
        }
      }
    }
    """)

    os.makedirs(os.path.dirname(os.path.abspath(out_file)), exist_ok=True)
    net.write_html(out_file)
    print(f"Enhanced visualization saved to {out_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Enhanced Bloom Visualization')
    parser.add_argument('--edges', required=True, help='Edge CSV file')
    parser.add_argument('--nodes', required=True, help='Node CSV file')
    parser.add_argument('--out',   default='out/subgraph.html', help='Output HTML file')
    args = parser.parse_args()
    visualize(args.edges, args.nodes, args.out)
