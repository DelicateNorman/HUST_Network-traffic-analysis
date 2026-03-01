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
 * Export all edges and nodes in the connected component containing 'ip'.
 * Edge CSV:
 * src_ip,dst_ip,total_bytes,total_duration,tcp_bytes,udp_bytes,icmp_bytes,other_bytes
 * Node CSV: ip,total_bytes,out_ratio,is_oneway,degree
 * @param g          built graph
 * @param ip         IP whose component to export
 * @param edge_file  output edge CSV file path
 * @param node_file  output node CSV file path
 * @return           number of edges exported, or -1 on error
 */
int export_subgraph(const Graph &g, const std::string &ip,
                    const std::string &edge_file, const std::string &node_file);
