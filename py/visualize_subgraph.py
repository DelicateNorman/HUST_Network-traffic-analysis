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
                  bgcolor='#fafafa', font_color='#333')
    
    # Fine-tuned physics for clean, well-spread layout
    net.force_atlas_2based(
        gravity=-35,
        central_gravity=0.003,
        spring_length=100,
        spring_strength=0.05,
        damping=0.5
    )

    # 4. Add Nodes with Color-Coded Status (all same small size)
    for node in G.nodes():
        attr = node_attr.get(node, {'total_bytes': 0, 'out_ratio': 0, 'is_oneway': 0, 'degree': 0})
        
        # Uniform small size - avoid overcrowding overlaps
        size = 10
        shape = 'dot'
        
        # Color encodes state:
        #   Red   (#FF3B30) = Anomaly / One-way outbound (potential scanner)
        #   Orange(#FF9500) = High-degree hub / gateway node (degree >= 10)
        #   Blue  (#007AFF) = Normal node (standard traffic)
        degree = attr['degree']
        if attr['is_oneway']:
            color = {'background': '#FF3B30', 'border': '#FF6B6B', 'highlight': {'background': '#FF6B6B', 'border': '#FF3B30'}}
            label_suffix = ' ⚠️'
        elif degree >= 10:
            color = {'background': '#FF9500', 'border': '#FFAB38', 'highlight': {'background': '#FFAB38', 'border': '#FF9500'}}
            label_suffix = ' ★'
        else:
            color = {'background': '#007AFF', 'border': '#409CFF', 'highlight': {'background': '#409CFF', 'border': '#007AFF'}}
            label_suffix = ''

        bytes_val = attr['total_bytes']
        title = (f"<b>Node: {node}</b><br>"
                 f"Total Traffic: {bytes_val:,} bytes<br>"
                 f"Outbound Ratio: {attr['out_ratio']:.1%}<br>"
                 f"Degree: {degree}<br>"
                 f"{'\u26a0\ufe0f ANOMALY: Highly Outbound (potential scanner)' if attr['is_oneway'] else ('\u2605 Hub/Gateway node' if degree >= 10 else 'Status: Normal')}")

        # Only show IP label (no suffix on label to keep it clean)
        net.add_node(node, label=node, title=title,
                     color=color, size=size, shape=shape,
                     borderWidth=2, font={'color': '#222', 'size': 11})

    # 5. Add Edges with Protocol Visuals
    for src, dst, data in G.edges(data=True):
        tb = data['weight']
        td = data['duration']
        tcp = data['tcp']
        udp = data['udp']
        icmp = data['icmp']
        
        # Edge width fixed (thin lines, clean look)
        width = 1
        
        # Edge color indicates protocol dominance
        if tcp > udp and tcp > icmp:
            color = {'color': '#007AFF88', 'highlight': '#007AFF'}
        elif udp > tcp and udp > icmp:
            color = {'color': '#FF950088', 'highlight': '#FF9500'}
        else:
            color = {'color': '#86868b55', 'highlight': '#86868b'}
            
        title = (f"<b>Connection: {src} → {dst}</b><br>"
                 f"Volume: {tb:,} bytes<br>"
                 f"Duration: {td:.2f}s<br>"
                 f"<hr>"
                 f"TCP: {tcp:,} bytes<br>"
                 f"UDP: {udp:,} bytes<br>"
                 f"ICMP: {icmp:,} bytes")
        
        net.add_edge(src, dst, title=title, width=width, color=color, arrows='to')

    # vis.js options: clean layout, light shadow, smooth curved edges
    net.set_options("""
    {
      "nodes": {
        "shadow": {
          "enabled": true,
          "color": "rgba(0,0,0,0.12)",
          "size": 6,
          "x": 2,
          "y": 2
        }
      },
      "edges": {
        "smooth": {
          "type": "curvedCW",
          "roundness": 0.15
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
