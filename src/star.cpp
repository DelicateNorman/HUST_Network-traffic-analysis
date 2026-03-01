#include "star.h"
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

/**
 * star.cpp
 * FR-5: Star topology detection using undirected neighbor sets.
 * Algorithm:
 *   1. Build undirected_neighbors[v] = set of all nodes adjacent to v (in or
 * out)
 *   2. For each candidate center C: if |neighbors| >= min_leaves and
 *      all neighbors n satisfy |undirected_neighbors[n]| == 1 (only C),
 *      then C is a star center.
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
    if ((int)neighbors.size() < min_leaves)
      continue;

    // Check all neighbors are leaves (only connected to c)
    bool is_star = true;
    for (int leaf : neighbors) {
      if (undirected[leaf].size() != 1) {
        is_star = false;
        break;
      }
    }
    if (!is_star)
      continue;

    StarTopology st;
    st.center = g.id_to_ip[c];
    for (int leaf : neighbors)
      st.leaves.push_back(g.id_to_ip[leaf]);
    std::sort(st.leaves.begin(), st.leaves.end());
    results.push_back(st);
  }
  return results;
}

void print_stars(const std::vector<StarTopology> &stars) {
  if (stars.empty()) {
    std::cout << "No star topology found (no center with >= required leaves)\n";
    return;
  }
  std::cout << "Found " << stars.size() << " star topology(ies):\n\n";
  for (const auto &s : stars) {
    std::cout << s.center << ": ";
    for (int i = 0; i < (int)s.leaves.size(); i++) {
      if (i > 0)
        std::cout << ", ";
      std::cout << s.leaves[i];
    }
    std::cout << "\n";
    std::cout << "  (Leaf count: " << s.leaves.size() << ")\n";
  }
}
