#pragma once
#include "graph.h"
#include <string>

/**
 * export.h
 * FR-9: Export a subgraph (connected component) to CSV for visualization.
 * Uses union-find on undirected edges to find connected component of a given
 * IP.
 */

/**
 * Export all edges in the connected component containing 'ip' to a CSV file.
 * CSV columns: src_ip,dst_ip,total_bytes,total_duration
 * @param g       built graph
 * @param ip      IP whose component to export
 * @param outfile output CSV file path
 * @return        number of edges exported, or -1 on error
 */
int export_subgraph(const Graph &g, const std::string &ip,
                    const std::string &outfile);
