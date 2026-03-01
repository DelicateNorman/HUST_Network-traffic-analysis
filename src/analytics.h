#pragma once
#include "csv_reader.h"
#include "graph.h"
#include <string>
#include <vector>

/**
 * analytics.h
 * FR-3: Traffic sorting and filtering.
 *   - sort:       All nodes by total traffic (out+in bytes), descending
 *   - sort-https: Nodes with HTTPS sessions (TCP, DstPort==443)
 *   - sort-oneway: Nodes where out/(out+in) > threshold
 */

struct NodeTrafficEntry {
  std::string ip;
  long long total_bytes;
  long long out_bytes;
  long long in_bytes;
  double out_ratio;
};

struct NodeHttpsEntry {
  std::string ip;
  long long https_bytes;
  long long https_out;
  long long https_in;
};

/**
 * FR-3.1: Sort all nodes by total traffic descending.
 * @param g    built graph
 * @param topk max entries to return (0 = all)
 */
std::vector<NodeTrafficEntry> sort_nodes_by_traffic(const Graph &g,
                                                    int topk = 20);

/**
 * FR-3.2: Filter nodes with HTTPS traffic (TCP proto=6, DstPort=443),
 * sort by HTTPS bytes descending.
 * @param sessions raw session records (needed to identify HTTPS sessions)
 * @param topk max entries
 */
std::vector<NodeHttpsEntry>
sort_nodes_https(const std::vector<SessionRecord> &sessions, const Graph &g,
                 int topk = 20);

/**
 * FR-3.3: Filter nodes where out/(out+in) > threshold, sort by total bytes
 * desc.
 * @param g         built graph
 * @param threshold default 0.8
 * @param topk      max entries
 */
std::vector<NodeTrafficEntry>
sort_nodes_oneway(const Graph &g, double threshold = 0.8, int topk = 50);

/// Print FR-3.1 / FR-3.3 results to stdout
void print_traffic(const std::vector<NodeTrafficEntry> &entries);
/// Print FR-3.2 results to stdout
void print_https(const std::vector<NodeHttpsEntry> &entries);
