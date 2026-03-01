# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Project Name:** Network Traffic Analyzer & Anomaly Detector（网络流量分析与异常检测系统）

**Language Requirements:** Core functionality must be C/C++; Python allowed for visualization/GUI/pcap extraction via subprocess or standalone scripts.

**Input Data:** data/network_data.csv (CSV with headers: Source, Destination, Protocol, SrcPort, DstPort, DataSize, Duration)

## Project Structure

The project requires a modular C++ implementation with the following recommended structure:

```
src/
  main.cpp              - Entry point
  cli.cpp / cli.h       - Argument parsing and command dispatch
  csv_reader.cpp / csv_reader.h - CSV file parsing
  ip_utils.cpp / ip_utils.h - IP string <-> uint32 conversion
  graph.cpp / graph.h   - Graph data structure (adjacency list)
  analytics.cpp / analytics.h - Sorting and statistics
  path.cpp / path.h     - BFS and Dijkstra algorithms
  star.cpp / star.h     - Star topology detection
  rules.cpp / rules.h   - Security rule engine
  export.cpp / export.h - Subgraph export (upgrade feature)

py/                     - Python scripts (optional)
  extract_pcap.py       - Extract data from pcap files
  visualize_subgraph.py - Graph visualization
  gui.py                - Python GUI (Tkinter/Streamlit)

out/                    - Output directory for exports
data/                   - Input data (network_data.csv exists)
```

## Build Commands

- **Initialize git:** `git init` (already done)
- **Commit after important features:** `git add . && git commit -m "description"`
- **Compile:** Use Makefile or CMakeLists.txt (not yet created)
- **Run:** `./app --help` to see all commands
- **Default input:** data/network_data.csv

## Important References

**Always reference Goals.txt for implementation details.** All functional requirements, algorithm constraints, data structures, and acceptance criteria are defined in Goals.txt. Before implementing any feature, read the relevant section in Goals.txt to ensure compliance with the exact specifications.

## Version Control

Use git for all code version control. Commit after completing important features:

- **Basic workflow:** `git add . && git commit -m "description"`
- **When to commit:** After completing each functional requirement (FR-1 through FR-9), bug fixes, or significant code refactoring
- **Commit message style:** Brief description in Chinese or English, e.g., "Implement CSV reader (FR-1)", "Add BFS path finding (FR-4)"

## Command-Line Interface

The application supports these subcommands:

| Command | Description |
|---------|-------------|
| `app load --input <path>` | Load CSV data |
| `app stats` | Print graph statistics |
| `app sort --top N` | Sort nodes by total traffic (descending) |
| `app sort-https --top N` | Sort nodes by HTTPS traffic |
| `app sort-oneway --threshold 0.8 --top N` | Sort nodes with outbound ratio > threshold |
| `app path --src <ip> --dst <ip> --metric hop\|congestion` | Find paths between two nodes |
| `app stars --min-leaves N` | Detect star topologies |
| `app rule iprange --mode deny\|allow --ip1 <ip> --low <ip> --high <ip>` | Apply IP range security rule |
| `app export-subgraph --ip <ip> --out <path>` | Export subgraph for visualization |

## Key Algorithms (Fixed Constraints)

- **Node total traffic:** out_bytes + in_bytes
- **HTTPS identification:** Protocol == 6 AND DstPort == 443
- **One-way node:** out_bytes / (out_bytes + in_bytes) > 0.8
- **Minimum hops:** BFS (unweighted)
- **Minimum congestion:** Dijkstra with edge weight = bytes/duration
- **Congestion definition:** flow/duration (sum of edge congestions for path)
- **Star topology:** Center node connected to >= 20 leaf nodes, leaves only connect to center (undirected)

## Edge Merge Rules

When building the graph, merge multiple sessions between the same (Source, Destination) pair into a single directed edge with aggregated stats:
- total_bytes: sum of all DataSize
- total_duration: sum of all Duration
- bytes_by_proto[proto]: breakdown by protocol (TCP/UDP/ICMP/others)
- dur_by_proto[proto]: duration breakdown by protocol
- session_count: number of sessions merged

## Data Structures

Key structs to implement:
- `SessionRecord` - Single CSV row
- `EdgeStats` - Aggregated edge statistics
- `Edge` - Directed edge with stats
- `Graph` - Adjacency list representation with node table

## Exit Codes

- 0: Success
- 2: Argument error
- 3: File I/O error
- 4: Node not found in graph
- 5: Path does not exist

## Output Format Requirements

- Traffic sorting: stable sort with secondary ordering by IP lexicographically
- Numbers: integers for bytes, 3 decimal places for ratios
- Path format: `IP1 -> IP2 -> ... -> IPn`

## Python Integration (Optional)

Python scripts communicate with C++ via subprocess. The C++ CLI should output plain text that Python can display directly. For pcap extraction, use Scapy to parse packets and output CSV format compatible with the main program.
