# Network Traffic Analyzer & Anomaly Detector

A comprehensive C/C++ command-line application that reads network session data from CSV, builds a directed graph, provides traffic sorting/filtering, path finding, star topology detection, security rules, and features a premium Apple-style Web GUI and visualization suite.

## What Was Built

The project implements all Functional Requirements (FR-1 through FR-9) as outlined in the project goals, including several premium upgrades for data visualization.

## Build Instructions

```bash
make
```
Requires: `g++` with C++17 support.
The build process compiles all source files in `src/` into a single executable `./app`.

## Verified CLI Commands & Expected Output

### FR-1 + FR-2: Load CSV & Graph Stats
```bash
./app stats
```
**Output Highlights:**
- Loaded 1264 sessions from `data/network_data.csv`
- Nodes (unique IPs): 1611
- Edges (merged): 1222
- Total bytes: 74,207,561 (TCP: 87.1%, UDP: 12.8%, ICMP: 0.04%)

### FR-3.1: Sort Nodes by Total Traffic
```bash
./app sort --top 5
```
**Output Highlights:**
Returns top nodes by total bytes (InBytes + OutBytes). e.g., IP `183.94.22.88` with 12MB.

### FR-3.2: Sort Nodes by HTTPS Traffic
```bash
./app sort-https --top 5
```
**Output Highlights:**
Filters for Protocol=6 and DstPort=443, sorting by HTTPS bytes.

### FR-3.3: Detect One-way Traffic Anomalies (e.g., Scanners)
```bash
./app sort-oneway --threshold 0.8 --top 5
```
**Output Highlights:**
Returns nodes where `OutBytes / TotalBytes > 0.8`. Found 50 highly outbound nodes.

### FR-4: Path Finding (BFS for Hops, Dijkstra for Congestion)
```bash
./app path --src 115.156.142.194 --dst 18.182.32.116 --metric both
```
**Output Highlights:**
Shows shortest path by hop count (1 hop) and minimum congestion path.

### FR-5: Detect Star Topologies
```bash
./app stars --min-leaves 20
```
**Output Highlights:**
Finds central nodes connected to >= 20 leaves (where leaves have degree=1).

### FR-6: Implement Security Rule (IP Range Block)
```bash
./app rule iprange --mode deny --ip1 115.156.142.194 --low 18.182.32.100 --high 18.182.32.200
```
**Output Highlights:**
Flags 14 sessions where `115.156.142.194` communicated with IPs in the blocked range.

### FR-7 & FR-9: Subgraph Export and Validation
```bash
./app export-subgraph --ip 115.156.142.194 --out out/subgraph_edges.csv
```
**Output Highlights:**
Uses BFS to isolate the connected component for the given IP, exporting 237 edges and 220 nodes to CSV with enriched metadata (traffic ratio, degree, etc).

## 🌸 "Make it Bloom" Enhancements: Premium Visualization & Native Web GUI (FR-8 & FR-9+)

The project has been upgraded from standard CLI/Tkinter outputs to a premium, Apple-style Native UI Web App with interactive graph visualizations.

### 1. Extract PCAP to CSV (FR-7)
```bash
pip install scapy
python3 py/extract_pcap.py --pcap capture.pcap --out data/network_data.csv
```

### 2. Run the Premium Web GUI
The GUI uses a lightweight `FastAPI` backend to interface with the C++ core, rendering a gorgeous semantic HTML/CSS frontend with glassmorphism and smooth animations.

```bash
# Install requirements
pip install fastapi uvicorn networkx pyvis

# Start the server
python3 -m uvicorn py.server:app --port 8000
```
**👉 Then open your browser to:** [http://localhost:8000](http://localhost:8000)

**Visualization Features:**
- **Dark Mode / Neon Aesthetic**: Deep `#0f0f1b` backgrounds with glowing elements.
- **Semantic Node Styling**: Node size scales via `log(traffic)`.
- **Anomaly Highlighting**: "One-way" scanning nodes glow red automatically.
- **Rich Tooltips**: Hover over nodes/edges for protocol breakdown (TCP/UDP/ICMP).

## Project Structure

```text
ProgramDesign/
├── src/          # C++ source code (main, graph, analytics, rules, etc)
├── py/           # Python bridge scripts (server.py, visualize_subgraph.py)
├── web/          # Apple-style Premium GUI assets (HTML/CSS/JS)
├── data/         # Input CSV directory
├── out/          # Exported CSVs and generated HTML graphs
└── Makefile      # Build script
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 2    | Argument error |
| 3    | File I/O error |
| 4    | Node not found |
| 5    | Path not found |
