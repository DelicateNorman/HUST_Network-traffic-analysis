# Network Traffic Analyzer & Anomaly Detector

A C/C++ command-line tool for analyzing network session data from CSV, detecting anomalies, and visualizing subgraphs.

## Build

```bash
make
```

Requires: `g++` with C++17 support.

## Quick Start

```bash
# Show help
./app --help

# Load stats
./app stats

# Top 20 nodes by traffic
./app sort --top 20

# Top 20 HTTPS nodes
./app sort-https --top 20

# One-way traffic nodes (>80% outbound)
./app sort-oneway --threshold 0.8 --top 50

# Path finding
./app path --src 115.156.142.194 --dst 18.182.32.116 --metric hop
./app path --src 115.156.142.194 --dst 18.182.32.116 --metric congestion
./app path --src 115.156.142.194 --dst 18.182.32.116 --metric both

# Star topology detection
./app stars --min-leaves 20

# Security rule: deny ip1 from communicating with range
./app rule iprange --mode deny --ip1 115.156.142.194 --low 18.0.0.0 --high 18.255.255.255

# Export subgraph
./app export-subgraph --ip 115.156.142.194 --out out/subgraph_edges.csv
```

## Upgrade Features

### PCAP Extraction (FR-7)
```bash
pip install scapy
python3 py/extract_pcap.py --pcap capture.pcap --out data/network_data.csv
```

### GUI (FR-8)
```bash
python3 py/gui.py
```

### Subgraph Visualization (FR-9)
```bash
pip install networkx pyvis
python3 py/visualize_subgraph.py --edges out/subgraph_edges.csv --out out/subgraph.html
```

## Project Structure

```
src/          C++ source files
py/           Python scripts
data/         Input CSV
out/          Exported data/visualizations
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 2    | Argument error |
| 3    | File I/O error |
| 4    | Node not found |
| 5    | Path not found |
