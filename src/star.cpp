#include "star.h"
#include <algorithm>
#include <iostream>
#include <unordered_set>

/**
 * @file star.cpp
 * @brief Star topology detection module (FR-5).
 *
 * Algorithm:
 *   1. Build undirected neighbor sets for each node.
 *   2. For each candidate center: if |neighbors| >= min_leaves and
 *      all neighbors satisfy |undirected_neighbors[n]| == 1 (only connected to
 * center), then that candidate is confirmed as a star center.
 */

/**
 * @brief Detects strict "star" shaped sub-topologies within the graph.
 * @param g The full Session Graph.
 * @param min_leaves Minimum number of strictly one-hop leaf nodes required to
 * qualify as a star center.
 * @return std::vector<StarTopology> List of discovered star topologies.
 */

std::vector<StarTopology> detect_stars(const Graph &g, int min_leaves) {
  int N = g.num_nodes();
  // Build undirected neighbor sets
  std::vector<std::unordered_set<int>> undirected(N);
  for (int u = 0; u < N; u++) {
    for (const auto &e : g.adj[u]) {
      int v = e.to;
      undirected[u].insert(v);
      undirected[v].insert(u);
    }
  }

  std::vector<StarTopology> results;
  for (int c = 0; c < N; c++) {
    const auto &neighbors = undirected[c];

    // Collect ONLY the pure-leaf neighbors: those whose only connection is to c
    std::vector<int> leaves;
    for (int leaf : neighbors) {
      if ((int)undirected[leaf].size() == 1) {
        // This neighbor connects ONLY to c — it is a true leaf
        leaves.push_back(leaf);
      }
    }

    if ((int)leaves.size() < min_leaves)
      continue;

    StarTopology st;
    st.center = g.id_to_ip[c];
    for (int leaf : leaves)
      st.leaves.push_back(g.id_to_ip[leaf]);
    std::sort(st.leaves.begin(), st.leaves.end());
    results.push_back(st);
  }
  return results;
}

void print_stars(const std::vector<StarTopology> &stars, bool json_output) {
  if (json_output) {
    std::cout << "[\n";
    for (size_t i = 0; i < stars.size(); i++) {
      std::cout << "  {\n"
                << "    \"center\": \"" << stars[i].center << "\",\n"
                << "    \"leaves\": [";
      for (size_t j = 0; j < stars[i].leaves.size(); j++) {
        std::cout << "\"" << stars[i].leaves[j] << "\""
                  << (j < stars[i].leaves.size() - 1 ? ", " : "");
      }
      std::cout << "]\n"
                << "  }" << (i < stars.size() - 1 ? "," : "") << "\n";
    }
    std::cout << "]\n";
    return;
  }

  if (stars.empty()) {
    std::cout << "No star topology found (no center with >= required leaves)\n";
    std::cout << "未检测到星型拓扑（不存在满足叶子节点数要求的中心节点）\n";
    return;
  }
  std::cout << "Found / 发现 " << stars.size()
            << " star topology(ies) / 星型结构:\n\n";
  for (const auto &s : stars) {
    std::cout << s.center << " (Center/中心节点): \n  Leaves/向外发散节点: ";
    for (int i = 0; i < (int)s.leaves.size(); i++) {
      if (i > 0)
        std::cout << ", ";
      std::cout << s.leaves[i];
    }
    std::cout << "\n";
    std::cout << "  (Leaf count / 叶子节点总数: " << s.leaves.size() << ")\n\n";
  }
}
