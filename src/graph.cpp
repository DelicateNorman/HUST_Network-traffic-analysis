#include "graph.h"
#include <stdexcept>

/**
 * graph.cpp
 * FR-2: Graph construction and edge merging.
 * Key algorithm: merge sessions with same (Source, Destination) into one edge.
 * Uses a temporary map<pair<int,int>, EdgeStats> to accumulate before building
 * adj list.
 */

int proto_index(int proto) {
  if (proto == 6)
    return 0; // TCP
  if (proto == 17)
    return 1; // UDP
  if (proto == 1)
    return 2; // ICMP
  return 3;   // other
}

int Graph::get_or_create(const std::string &ip) {
  auto it = ip_to_id.find(ip);
  if (it != ip_to_id.end())
    return it->second;
  int id = (int)id_to_ip.size();
  ip_to_id[ip] = id;
  id_to_ip.push_back(ip);
  adj.emplace_back();
  out_bytes.push_back(0);
  in_bytes.push_back(0);
  return id;
}

const Edge *Graph::find_edge(int u, int v) const {
  for (const auto &e : adj[u]) {
    if (e.to == v)
      return &e;
  }
  return nullptr;
}

Graph build_graph(const std::vector<SessionRecord> &sessions) {
  Graph g;

  // Phase 1: accumulate edge stats using unordered_map with string key "u->v"
  // Use a two-level map: src_id -> (dst_id -> EdgeStats)
  // We first register all nodes then accumulate edges.

  // Pre-register nodes
  for (const auto &s : sessions) {
    g.get_or_create(s.source);
    g.get_or_create(s.destination);
  }

  // Temporary adjacency map: adj_map[u][v] = EdgeStats
  int N = g.num_nodes();
  // Use flat map per source node
  std::vector<std::unordered_map<int, EdgeStats>> adj_map(N);

  for (const auto &s : sessions) {
    int u = g.ip_to_id[s.source];
    int v = g.ip_to_id[s.destination];

    auto &es = adj_map[u][v];
    es.total_bytes += s.data_size;
    es.total_duration += s.duration;
    int pi = proto_index(s.protocol);
    es.bytes_by_proto[pi] += s.data_size;
    es.dur_by_proto[pi] += s.duration;
    es.session_count++;

    // Accumulate node-level byte counters
    g.out_bytes[u] += s.data_size;
    g.in_bytes[v] += s.data_size;
  }

  // Phase 2: move into adjacency list
  for (int u = 0; u < N; u++) {
    for (auto &kv : adj_map[u]) {
      Edge e;
      e.to = kv.first;
      e.stats = kv.second;
      g.adj[u].push_back(e);
    }
  }

  return g;
}
