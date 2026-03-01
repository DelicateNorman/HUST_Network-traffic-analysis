#include "export.h"
#include <fstream>
#include <iostream>
#include <queue>
#include <unordered_set>
#include <vector>

/**
 * export.cpp
 * FR-9: Subgraph export using union-find (BFS on undirected edges).
 * Finds the connected component containing the given IP and exports its edges.
 */

int export_subgraph(const Graph &g, const std::string &ip,
                    const std::string &outfile) {
  // Find node id for the given IP
  auto it = g.ip_to_id.find(ip);
  if (it == g.ip_to_id.end()) {
    std::cerr << "[ERROR] IP not found in graph: " << ip << "\n";
    return -1;
  }
  int start = it->second;
  int N = g.num_nodes();

  // BFS on undirected graph to find all nodes in the same component
  std::vector<bool> visited(N, false);
  std::queue<int> q;
  visited[start] = true;
  q.push(start);

  // Build reverse adjacency for undirected BFS
  std::vector<std::unordered_set<int>> undirected(N);
  for (int u = 0; u < N; u++) {
    for (const auto &e : g.adj[u]) {
      undirected[u].insert(e.to);
      undirected[e.to].insert(u);
    }
  }

  while (!q.empty()) {
    int u = q.front();
    q.pop();
    for (int v : undirected[u]) {
      if (!visited[v]) {
        visited[v] = true;
        q.push(v);
      }
    }
  }

  // Open output file
  std::ofstream f(outfile);
  if (!f.is_open()) {
    std::cerr << "[ERROR] Cannot open output file: " << outfile << "\n";
    return -1;
  }

  // Write header
  f << "src_ip,dst_ip,total_bytes,total_duration\n";
  int count = 0;
  for (int u = 0; u < N; u++) {
    if (!visited[u])
      continue;
    for (const auto &e : g.adj[u]) {
      if (!visited[e.to])
        continue;
      f << g.id_to_ip[u] << "," << g.id_to_ip[e.to] << ","
        << e.stats.total_bytes << "," << std::fixed << e.stats.total_duration
        << "\n";
      count++;
    }
  }
  f.close();

  std::cout << "Exported " << count << " edges to " << outfile << "\n";
  return count;
}
