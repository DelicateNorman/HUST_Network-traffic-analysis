#pragma once
#include "graph.h"
#include <string>
#include <vector>

/**
 * star.h
 * FR-5: Star topology detection.
 * Definition (undirected): center node C with >= min_leaves neighbors,
 * where each leaf node only connects to C (and no other node).
 */

struct StarTopology {
  std::string center;              ///< center IP
  std::vector<std::string> leaves; ///< leaf IP list
};

/**
 * Detect all star topologies in the graph.
 * Uses undirected neighbor sets.
 * @param g          built graph
 * @param min_leaves minimum number of leaves required (default 20)
 * @return           list of detected star topologies
 */
std::vector<StarTopology> detect_stars(const Graph &g, int min_leaves = 20);

/**
 * @brief Prints the discovered star topologies to standard output.
 * @param stars List of StarTopology objects to print.
 */
void print_stars(const std::vector<StarTopology> &stars,
                 bool json_output = false);
