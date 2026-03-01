#pragma once
#include "graph.h"
#include <string>
#include <vector>

/**
 * path.h
 * FR-4: Path finding between two nodes.
 *   - BFS for minimum hop count (unweighted)
 *   - Dijkstra for minimum congestion (edge weight =
 * total_bytes/total_duration)
 */

struct PathResult {
  bool found = false;
  std::vector<int> node_ids; ///< sequence of node ids from src to dst
  int hops = 0;              ///< number of edges (for BFS)
  double cost = 0.0;         ///< total congestion cost (for Dijkstra)
};

/**
 * BFS shortest path by hop count.
 * @param g    graph
 * @param src  source node id
 * @param dst  destination node id
 * @return     PathResult with found flag, node path, hop count
 */
PathResult bfs_path(const Graph &g, int src, int dst);

/**
 * Dijkstra minimum congestion path.
 * Edge weight = total_bytes / total_duration (skip edges with duration <= 0).
 * Path cost = sum of edge congestion values.
 * @param g    graph
 * @param src  source node id
 * @param dst  destination node id
 * @return     PathResult with found flag, node path, total cost
 */
PathResult dijkstra_path(const Graph &g, int src, int dst);

/// Format a path as "IP1 -> IP2 -> ... -> IPn"
std::string format_path(const Graph &g, const std::vector<int> &ids);

/// Print comparison of two paths
void print_path_comparison(const Graph &g, const PathResult &hop_result,
                           const PathResult &cong_result);
