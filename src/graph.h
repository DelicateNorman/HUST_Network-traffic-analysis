#pragma once
#include "csv_reader.h"
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

/**
 * graph.h
 * FR-2: Directed graph built from network sessions.
 * Nodes = unique IPs; Edges = merged sessions between same (src, dst) pair.
 */

/// Aggregated statistics for a directed edge (src -> dst)
struct EdgeStats {
  long long total_bytes = 0;
  double total_duration = 0.0;
  long long bytes_by_proto[4] = {
      0, 0, 0, 0}; ///< [0]=TCP(6),[1]=UDP(17),[2]=ICMP(1),[3]=other
  double dur_by_proto[4] = {0, 0, 0, 0};
  int session_count = 0;
};

/// A single directed edge in the adjacency list
struct Edge {
  int to; ///< destination node id
  EdgeStats stats;
};

/// The directed graph with adjacency list representation
struct Graph {
  std::unordered_map<std::string, int> ip_to_id; ///< ip string -> node id
  std::vector<std::string> id_to_ip;             ///< node id -> ip string
  std::vector<std::vector<Edge>> adj;            ///< adjacency list

  // Per-node byte totals (out/in) computed during build
  std::vector<long long> out_bytes; ///< total bytes sent by this node
  std::vector<long long> in_bytes;  ///< total bytes received by this node

  int num_nodes() const { return (int)id_to_ip.size(); }
  int num_edges() const {
    int cnt = 0;
    for (auto &v : adj)
      cnt += (int)v.size();
    return cnt;
  }

  /// Get or create node id for an IP string
  int get_or_create(const std::string &ip);

  /// Find edge from u to v; returns nullptr if not found
  const Edge *find_edge(int u, int v) const;
};

/**
 * Build graph from session records.
 * Merges multiple sessions between same (Source, Destination) into one edge.
 * @param sessions  parsed session records
 * @return          constructed Graph
 */
Graph build_graph(const std::vector<SessionRecord> &sessions);

/// Protocol index helper (0=TCP, 1=UDP, 2=ICMP, 3=other)
int proto_index(int proto);
