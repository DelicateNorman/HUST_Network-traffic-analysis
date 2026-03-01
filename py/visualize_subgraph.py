#!/usr/bin/env python3
"""
visualize_subgraph.py - FR-9: Visualize a subgraph exported by ./app export-subgraph.
Usage: python3 py/visualize_subgraph.py --edges out/subgraph_edges.csv --out out/subgraph.html

Requires: networkx, pyvis (pip install networkx pyvis)
"""

import argparse
import csv
import sys
import os

def visualize(edges_file, out_file):
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
    edge_count = 0

    with open(edges_file, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            src = row['src_ip']
            dst = row['dst_ip']
            tb  = int(row['total_bytes'])
            td  = float(row['total_duration'])
            G.add_edge(src, dst, weight=tb, duration=td)
            edge_count += 1

    print(f"Loaded {G.number_of_nodes()} nodes, {edge_count} edges")

    # Build pyvis network
    net = Network(height='800px', width='100%', directed=True,
                  bgcolor='#1a1a2e', font_color='#eee')
    net.force_atlas_2based(gravity=-50, central_gravity=0.01,
                           spring_length=100, spring_strength=0.05)
    net.show_buttons(filter_=['physics'])

    # Color nodes by degree
    max_deg = max((G.degree(n) for n in G.nodes()), default=1)
    for node in G.nodes():
        deg = G.degree(node)
        # Color: blue for low degree, red for high
        ratio = deg / max_deg if max_deg > 0 else 0
        r = int(50 + 200 * ratio)
        b = int(50 + 200 * (1 - ratio))
        color = f'#{r:02x}50{b:02x}'
        net.add_node(node, label=node, title=f"{node}\nDegree: {deg}",
                     color=color, size=8 + deg * 2)

    for src, dst, data in G.edges(data=True):
        tb = data.get('weight', 0)
        td = data.get('duration', 0)
        title = f"{src} → {dst}\nBytes: {tb}\nDuration: {td:.2f}s"
        width = max(1, min(10, tb // 10000))
        net.add_edge(src, dst, title=title, width=width, arrows='to')

    os.makedirs(os.path.dirname(os.path.abspath(out_file)), exist_ok=True)
    net.write_html(out_file)
    print(f"Visualization saved to {out_file}")
    print(f"Open in browser: file://{os.path.abspath(out_file)}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Visualize subgraph from edge CSV')
    parser.add_argument('--edges', default='out/subgraph_edges.csv', help='Edge CSV file')
    parser.add_argument('--out',   default='out/subgraph.html',      help='Output HTML file')
    args = parser.parse_args()
    visualize(args.edges, args.out)
