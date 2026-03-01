#include "analytics.h"
#include "cli.h"
#include "csv_reader.h"
#include "export.h"
#include "graph.h"
#include "path.h"
#include "rules.h"
#include "star.h"
#include <cstdlib>
#include <iomanip>
#include <iostream>

/**
 * main.cpp
 * Entry point: parse args, load CSV, build graph, dispatch command.
 * Exit codes:
 *   0 = success, 2 = arg error, 3 = file I/O error,
 *   4 = node not found, 5 = path not found
 */

static void print_stats(const ReadResult &rr, const Graph &g) {
  std::cout << "=== CSV Load Summary ===\n";
  std::cout << "Total data lines: " << rr.total_lines << "\n";
  std::cout << "Parsed OK:        " << rr.parsed_ok << "\n";
  std::cout << "Skipped:          " << rr.skipped << "\n\n";
  std::cout << "=== Graph Statistics ===\n";
  std::cout << "Nodes (unique IPs): " << g.num_nodes() << "\n";
  std::cout << "Edges (merged):     " << g.num_edges() << "\n";

  // Protocol distribution across sessions
  long long tcp = 0, udp = 0, icmp = 0, other = 0, total_bytes = 0;
  for (int u = 0; u < g.num_nodes(); u++) {
    for (const auto &e : g.adj[u]) {
      tcp += e.stats.bytes_by_proto[0];
      udp += e.stats.bytes_by_proto[1];
      icmp += e.stats.bytes_by_proto[2];
      other += e.stats.bytes_by_proto[3];
      total_bytes += e.stats.total_bytes;
    }
  }
  std::cout << "Total bytes (sum of edges): " << total_bytes << "\n";
  std::cout << "Protocol breakdown:\n";
  if (total_bytes > 0) {
    std::cout << std::fixed << std::setprecision(1);
    std::cout << "  TCP:   " << tcp << " bytes (" << 100.0 * tcp / total_bytes
              << "%)\n";
    std::cout << "  UDP:   " << udp << " bytes (" << 100.0 * udp / total_bytes
              << "%)\n";
    std::cout << "  ICMP:  " << icmp << " bytes (" << 100.0 * icmp / total_bytes
              << "%)\n";
    std::cout << "  Other: " << other << " bytes ("
              << 100.0 * other / total_bytes << "%)\n";
  }
}

int main(int argc, char *argv[]) {
  CliOptions opts = parse_args(argc, argv);

  // Load CSV (always needed)
  ReadResult rr = read_csv(opts.input_file);
  if (rr.parsed_ok == 0 && rr.total_lines == 0) {
    return 3; // file I/O error
  }

  // Print load summary for every command
  std::cout << "Loaded " << rr.parsed_ok << " sessions from " << opts.input_file
            << " (skipped " << rr.skipped << " lines)\n\n";

  // Optional dump
  if (opts.dump_n > 0) {
    int n = std::min(opts.dump_n, (int)rr.records.size());
    std::cout << "=== First " << n << " session records ===\n";
    std::cout << std::left << std::setw(18) << "Source" << std::setw(18)
              << "Destination" << std::setw(6) << "Proto" << std::setw(8)
              << "SrcPort" << std::setw(8) << "DstPort" << std::setw(12)
              << "DataSize"
              << "Duration\n";
    for (int i = 0; i < n; i++) {
      const auto &s = rr.records[i];
      std::cout << std::left << std::setw(18) << s.source << std::setw(18)
                << s.destination << std::setw(6) << s.protocol << std::setw(8)
                << s.src_port << std::setw(8) << s.dst_port << std::setw(12)
                << s.data_size << s.duration << "\n";
    }
    std::cout << "\n";
  }

  // Build graph
  Graph g = build_graph(rr.records);

  // Optional show-node
  if (!opts.show_node_ip.empty()) {
    auto it = g.ip_to_id.find(opts.show_node_ip);
    if (it == g.ip_to_id.end()) {
      std::cerr << "[ERROR] Node not found: " << opts.show_node_ip << "\n";
      return 4;
    }
    int u = it->second;
    std::cout << "Node " << opts.show_node_ip << " adjacency:\n";
    std::cout << std::left << std::setw(20) << "Destination" << std::setw(12)
              << "TotalBytes" << std::setw(12) << "Duration"
              << "Sessions\n";
    for (const auto &e : g.adj[u]) {
      std::cout << std::left << std::setw(20) << g.id_to_ip[e.to]
                << std::setw(12) << e.stats.total_bytes << std::fixed
                << std::setprecision(3) << std::setw(12)
                << e.stats.total_duration << e.stats.session_count << "\n";
    }
    std::cout << "\n";
  }

  // Dispatch command
  const std::string &cmd = opts.command;

  if (cmd == "stats") {
    print_stats(rr, g);
  } else if (cmd == "sort") {
    std::cout << "=== Top " << opts.top_k << " Nodes by Total Traffic ===\n";
    auto entries = sort_nodes_by_traffic(g, opts.top_k);
    print_traffic(entries);
  } else if (cmd == "sort-https") {
    std::cout << "=== Top " << opts.top_k << " Nodes by HTTPS Traffic ===\n";
    auto entries = sort_nodes_https(rr.records, g, opts.top_k);
    print_https(entries);
  } else if (cmd == "sort-oneway") {
    std::cout << "=== Nodes with Outbound Ratio > " << opts.threshold
              << " (Top " << opts.top_k << ") ===\n";
    auto entries = sort_nodes_oneway(g, opts.threshold, opts.top_k);
    print_traffic(entries);
    std::cout << "Total one-way nodes found: " << entries.size() << "\n";
  } else if (cmd == "path") {
    if (opts.src_ip.empty() || opts.dst_ip.empty()) {
      std::cerr << "[ERROR] --src and --dst are required for path command\n";
      return 2;
    }
    auto src_it = g.ip_to_id.find(opts.src_ip);
    auto dst_it = g.ip_to_id.find(opts.dst_ip);
    if (src_it == g.ip_to_id.end()) {
      std::cerr << "[ERROR] Source IP not found: " << opts.src_ip << "\n";
      return 4;
    }
    if (dst_it == g.ip_to_id.end()) {
      std::cerr << "[ERROR] Destination IP not found: " << opts.dst_ip << "\n";
      return 4;
    }
    int src = src_it->second;
    int dst = dst_it->second;

    if (opts.metric == "hop") {
      auto pr = bfs_path(g, src, dst);
      if (!pr.found) {
        std::cout << "No path found from " << opts.src_ip << " to "
                  << opts.dst_ip << "\n";
        return 5;
      }
      std::cout << "=== Minimum Hops Path ===\n";
      std::cout << "Path: " << format_path(g, pr.node_ids) << "\n";
      std::cout << "Hops: " << pr.hops << "\n";
    } else if (opts.metric == "congestion") {
      auto pr = dijkstra_path(g, src, dst);
      if (!pr.found) {
        std::cout << "No path found from " << opts.src_ip << " to "
                  << opts.dst_ip << "\n";
        return 5;
      }
      std::cout << "=== Minimum Congestion Path (Dijkstra) ===\n";
      std::cout << "Path:               " << format_path(g, pr.node_ids)
                << "\n";
      std::cout << "Hops:               " << pr.hops << "\n";
      std::cout << std::fixed << std::setprecision(4);
      std::cout << "Total Congestion:   " << pr.cost << " bytes/s\n";
    } else if (opts.metric == "both") {
      auto hop_pr = bfs_path(g, src, dst);
      auto cong_pr = dijkstra_path(g, src, dst);
      print_path_comparison(g, hop_pr, cong_pr);
      if (!hop_pr.found && !cong_pr.found)
        return 5;
    } else {
      // Default: show both
      std::cout << "Metric: both (hop + congestion)\n";
      auto hop_pr = bfs_path(g, src, dst);
      auto cong_pr = dijkstra_path(g, src, dst);
      print_path_comparison(g, hop_pr, cong_pr);
      if (!hop_pr.found && !cong_pr.found)
        return 5;
    }
  } else if (cmd == "stars") {
    std::cout << "=== Star Topology Detection (min-leaves=" << opts.min_leaves
              << ") ===\n";
    auto stars = detect_stars(g, opts.min_leaves);
    print_stars(stars);
  } else if (cmd == "rule-iprange") {
    if (opts.rule_mode.empty() || opts.ip1.empty() || opts.ip_low.empty() ||
        opts.ip_high.empty()) {
      std::cerr
          << "[ERROR] rule iprange requires --mode, --ip1, --low, --high\n";
      return 2;
    }
    std::cout << "=== IP Range Rule [" << opts.rule_mode << "] ===\n";
    std::cout << "IP1: " << opts.ip1 << "\n";
    std::cout << "Range: [" << opts.ip_low << " - " << opts.ip_high << "]\n\n";
    auto violations = apply_iprange_rule(rr.records, opts.ip1, opts.ip_low,
                                         opts.ip_high, opts.rule_mode);
    print_violations(violations);
  } else if (cmd == "export-subgraph") {
    if (opts.export_ip.empty()) {
      std::cerr << "[ERROR] --ip is required for export-subgraph\n";
      return 2;
    }
    // Derive node file path from edge file path
    std::string edge_file = opts.out_file;
    std::string node_file = edge_file;
    size_t last_dot = node_file.find_last_of('.');
    if (last_dot != std::string::npos) {
      node_file.insert(last_dot, "_nodes");
    } else {
      node_file += "_nodes.csv";
    }

    int ret = export_subgraph(g, opts.export_ip, edge_file, node_file);
    if (ret < 0)
      return 3;
    if (ret == 0) {
      std::cerr << "[WARN] Subgraph has no edges.\n";
    }
  } else if (cmd == "load") {
    // Just load and show stats
    print_stats(rr, g);
  } else {
    std::cerr << "[ERROR] Unknown command: " << cmd << "\n";
    std::cerr << "Use --help to see available commands.\n";
    return 2;
  }

  return 0;
}
