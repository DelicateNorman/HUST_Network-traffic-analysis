#include "export.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <queue>
#include <unordered_set>
#include <vector>

/**
 * @file export.cpp
 * @brief Handles enhanced subgraph exporting (FR-9).
 *
 * Given a target IP address, this module locates the node, performs a
 * Breadth-First Search to identify its connected component within the
 * undirected form of the graph, and exports the enriched edges and nodes to
 * separate CSV files for downstream visualizations.
 */

/**
 * @brief Exports an isolated connected component containing a designated IP to
 * CSV files.
 *
 * @param g The full Session Graph.
 * @param ip The IP address forming part of the target subnetwork.
 * @param edge_file Path to save the extracted edges.
 * @param node_file Path to save the extracted nodes with structural metadata.
 * @return Number of edges successfully exported, or -1 on error.
 */
int export_subgraph(const Graph &g, const std::string &ip,
                    const std::string &edge_file,
                    const std::string &node_file) {
  // Find node id for the given IP
  auto it = g.ip_to_id.find(ip);
  if (it == g.ip_to_id.end()) {
    std::cerr << "[ERROR] IP not found in graph / 当前全图中不存在指定的IP: "
              << ip << "\n";
    return -1;
  }
  int start = it->second;
  int N = g.num_nodes();

  // BFS on undirected graph to find all nodes in the same component
  std::vector<bool> visited(N, false);
  std::queue<int> q;
  visited[start] = true;
  q.push(start);

  // Build degree and undirected adjacency
  std::vector<int> degree(N, 0);
  std::vector<std::unordered_set<int>> undirected(N);
  for (int u = 0; u < N; u++) {
    for (const auto &e : g.adj[u]) {
      undirected[u].insert(e.to);
      undirected[e.to].insert(u);
    }
  }
  for (int u = 0; u < N; u++) {
    degree[u] = (int)undirected[u].size();
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

  // ─── Export Edges ───
  std::ofstream ef(edge_file);
  if (!ef.is_open()) {
    std::cerr << "[ERROR] Cannot open edge file / 无法创建边导出文件: "
              << edge_file << "\n";
    return -1;
  }
  ef << "src_ip,dst_ip,total_bytes,total_duration,tcp_bytes,udp_bytes,icmp_"
        "bytes,other_bytes\n";
  int edge_count = 0;
  for (int u = 0; u < N; u++) {
    if (!visited[u])
      continue;
    for (const auto &e : g.adj[u]) {
      if (!visited[e.to])
        continue;
      const auto &s = e.stats;
      ef << g.id_to_ip[u] << "," << g.id_to_ip[e.to] << "," << s.total_bytes
         << "," << std::fixed << std::setprecision(3) << s.total_duration << ","
         << s.bytes_by_proto[0] << "," << s.bytes_by_proto[1] << ","
         << s.bytes_by_proto[2] << "," << s.bytes_by_proto[3] << "\n";
      edge_count++;
    }
  }
  ef.close();

  // ─── Export Nodes ───
  std::ofstream nf(node_file);
  if (!nf.is_open()) {
    std::cerr << "[ERROR] Cannot open node file / 无法创建节点导出文件: "
              << node_file << "\n";
    return -1;
  }
  nf << "ip,total_bytes,out_ratio,is_oneway,degree\n";
  for (int u = 0; u < N; u++) {
    if (!visited[u])
      continue;
    long long total = g.out_bytes[u] + g.in_bytes[u];
    double ratio = (total > 0) ? (double)g.out_bytes[u] / total : 0.0;
    nf << g.id_to_ip[u] << "," << total << "," << std::fixed
       << std::setprecision(3) << ratio << "," << (ratio > 0.8 ? 1 : 0) << ","
       << degree[u] << "\n";
  }
  nf.close();

  std::cout << "Subgraph for " << ip << " exported / 连通子图提取完毕:\n";
  std::cout << "  Edges / 数据边数: " << edge_count << " -> " << edge_file
            << "\n";
  std::cout << "  Nodes in component / 组件内节点数: "
            << std::count(visited.begin(), visited.end(), true) << " -> "
            << node_file << "\n";

  return edge_count;
}
