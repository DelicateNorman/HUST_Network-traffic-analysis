#include "path.h"
#include <iomanip>
#include <iostream>
#include <limits>
#include <queue>
#include <vector>

/**
 * path.cpp
 * FR-4: BFS (min hops) and Dijkstra (min congestion) path finding.
 * Both algorithms reconstruct the path using a prev[] array.
 */

// BFS: minimum hop count path
PathResult bfs_path(const Graph &g, int src, int dst) {
  PathResult result;
  int N = g.num_nodes();
  if (src < 0 || src >= N || dst < 0 || dst >= N)
    return result;
  if (src == dst) {
    result.found = true;
    result.node_ids = {src};
    result.hops = 0;
    return result;
  }

  std::vector<int> prev(N, -1);
  std::vector<bool> visited(N, false);
  std::queue<int> q;

  visited[src] = true;
  q.push(src);

  while (!q.empty()) {
    int u = q.front();
    q.pop();
    if (u == dst)
      break;
    for (const auto &e : g.adj[u]) {
      int v = e.to;
      if (!visited[v]) {
        visited[v] = true;
        prev[v] = u;
        q.push(v);
      }
    }
  }

  if (!visited[dst])
    return result; // no path

  // Reconstruct path
  result.found = true;
  std::vector<int> path;
  for (int cur = dst; cur != -1; cur = prev[cur])
    path.push_back(cur);
  std::reverse(path.begin(), path.end());
  result.node_ids = path;
  result.hops = (int)path.size() - 1;
  return result;
}

// Dijkstra: minimum congestion path
// Edge weight = total_bytes / total_duration; skip edges with duration <= 0
PathResult dijkstra_path(const Graph &g, int src, int dst) {
  PathResult result;
  int N = g.num_nodes();
  if (src < 0 || src >= N || dst < 0 || dst >= N)
    return result;
  if (src == dst) {
    result.found = true;
    result.node_ids = {src};
    result.cost = 0.0;
    return result;
  }

  const double INF = std::numeric_limits<double>::infinity();
  std::vector<double> dist(N, INF);
  std::vector<int> prev(N, -1);
  // min-heap: (cost, node)
  using P = std::pair<double, int>;
  std::priority_queue<P, std::vector<P>, std::greater<P>> pq;

  dist[src] = 0.0;
  pq.push({0.0, src});

  while (!pq.empty()) {
    auto [d, u] = pq.top();
    pq.pop();
    if (d > dist[u])
      continue; // stale entry
    if (u == dst)
      break;

    for (const auto &e : g.adj[u]) {
      int v = e.to;
      const EdgeStats &es = e.stats;
      if (es.total_duration <= 0.0)
        continue; // skip unusable edges
      double weight = (double)es.total_bytes / es.total_duration;
      double nd = dist[u] + weight;
      if (nd < dist[v]) {
        dist[v] = nd;
        prev[v] = u;
        pq.push({nd, v});
      }
    }
  }

  if (dist[dst] == INF)
    return result; // no path

  result.found = true;
  result.cost = dist[dst];
  std::vector<int> path;
  for (int cur = dst; cur != -1; cur = prev[cur])
    path.push_back(cur);
  std::reverse(path.begin(), path.end());
  result.node_ids = path;
  result.hops = (int)path.size() - 1;
  return result;
}

std::string format_path(const Graph &g, const std::vector<int> &ids) {
  std::string s;
  for (int i = 0; i < (int)ids.size(); i++) {
    if (i > 0)
      s += " -> ";
    s += g.id_to_ip[ids[i]];
  }
  return s;
}

void print_path_comparison(const Graph &g, const PathResult &hop_result,
                           const PathResult &cong_result) {
  std::cout << "\n=== Path Comparison ===\n";
  std::cout << "[Minimum Hops (BFS)]\n";
  if (!hop_result.found) {
    std::cout << "  No path found\n";
  } else {
    std::cout << "  Path: " << format_path(g, hop_result.node_ids) << "\n";
    std::cout << "  Hops: " << hop_result.hops << "\n";
  }

  std::cout << "\n[Minimum Congestion (Dijkstra)]\n";
  if (!cong_result.found) {
    std::cout << "  No path found\n";
  } else {
    std::cout << "  Path: " << format_path(g, cong_result.node_ids) << "\n";
    std::cout << "  Hops: " << cong_result.hops << "\n";
    std::cout << "  Total Congestion: " << std::fixed << std::setprecision(4)
              << cong_result.cost << " bytes/s\n";
  }

  if (hop_result.found && cong_result.found) {
    std::cout << "\n[Difference]\n";
    std::cout << "  Hop difference: " << (cong_result.hops - hop_result.hops)
              << " hops\n";
    bool same = (hop_result.node_ids == cong_result.node_ids);
    std::cout << "  Same path: " << (same ? "Yes" : "No") << "\n";
  }
}
