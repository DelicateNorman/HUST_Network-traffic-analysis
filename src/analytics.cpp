#include "analytics.h"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <unordered_map>

/**
 * analytics.cpp
 * FR-3: Implementation of traffic sorting and filtering.
 */

// Helper: secondary sort by IP string for stability
static bool cmp_traffic(const NodeTrafficEntry &a, const NodeTrafficEntry &b) {
  if (a.total_bytes != b.total_bytes)
    return a.total_bytes > b.total_bytes;
  return a.ip < b.ip;
}

static bool cmp_https(const NodeHttpsEntry &a, const NodeHttpsEntry &b) {
  if (a.https_bytes != b.https_bytes)
    return a.https_bytes > b.https_bytes;
  return a.ip < b.ip;
}

// FR-3.1: Sort all nodes by total traffic (out+in)
std::vector<NodeTrafficEntry> sort_nodes_by_traffic(const Graph &g, int topk) {
  std::vector<NodeTrafficEntry> result;
  int N = g.num_nodes();
  result.reserve(N);

  for (int i = 0; i < N; i++) {
    NodeTrafficEntry e;
    e.ip = g.id_to_ip[i];
    e.out_bytes = g.out_bytes[i];
    e.in_bytes = g.in_bytes[i];
    e.total_bytes = e.out_bytes + e.in_bytes;
    e.out_ratio =
        (e.total_bytes > 0) ? (double)e.out_bytes / e.total_bytes : 0.0;
    result.push_back(e);
  }

  std::sort(result.begin(), result.end(), cmp_traffic);
  if (topk > 0 && (int)result.size() > topk)
    result.resize(topk);
  return result;
}

// FR-3.2: HTTPS nodes - Protocol==6, DstPort==443
std::vector<NodeHttpsEntry>
sort_nodes_https(const std::vector<SessionRecord> &sessions, const Graph &g,
                 int topk) {
  // Accumulate HTTPS bytes per IP (out + in)
  std::unordered_map<std::string, long long> https_out_map, https_in_map;

  for (const auto &s : sessions) {
    if (s.protocol == 6 && s.dst_port == 443) {
      https_out_map[s.source] += s.data_size;
      https_in_map[s.destination] += s.data_size;
    }
  }

  // Collect all IPs that appear
  std::unordered_map<std::string, NodeHttpsEntry> combined;
  for (auto &kv : https_out_map) {
    combined[kv.first].ip = kv.first;
    combined[kv.first].https_out += kv.second;
  }
  for (auto &kv : https_in_map) {
    combined[kv.first].ip = kv.first;
    combined[kv.first].https_in += kv.second;
  }

  std::vector<NodeHttpsEntry> result;
  result.reserve(combined.size());
  for (auto &kv : combined) {
    auto &e = kv.second;
    e.https_bytes = e.https_out + e.https_in;
    result.push_back(e);
  }

  std::sort(result.begin(), result.end(), cmp_https);
  if (topk > 0 && (int)result.size() > topk)
    result.resize(topk);
  return result;
}

// FR-3.3: One-way nodes
std::vector<NodeTrafficEntry> sort_nodes_oneway(const Graph &g,
                                                double threshold, int topk) {
  std::vector<NodeTrafficEntry> result;
  int N = g.num_nodes();

  for (int i = 0; i < N; i++) {
    long long ob = g.out_bytes[i];
    long long ib = g.in_bytes[i];
    long long total = ob + ib;
    if (total == 0)
      continue;
    double ratio = (double)ob / total;
    if (ratio > threshold) {
      NodeTrafficEntry e;
      e.ip = g.id_to_ip[i];
      e.out_bytes = ob;
      e.in_bytes = ib;
      e.total_bytes = total;
      e.out_ratio = ratio;
      result.push_back(e);
    }
  }

  std::sort(result.begin(), result.end(), cmp_traffic);
  if (topk > 0 && (int)result.size() > topk)
    result.resize(topk);
  return result;
}

void print_traffic(const std::vector<NodeTrafficEntry> &entries) {
  std::cout << std::left << std::setw(6) << "Rank" << std::setw(20) << "IP"
            << std::setw(15) << "TotalBytes" << std::setw(15) << "OutBytes"
            << std::setw(15) << "InBytes" << std::setw(10) << "OutRatio"
            << "\n";
  std::cout << std::string(81, '-') << "\n";
  for (int i = 0; i < (int)entries.size(); i++) {
    const auto &e = entries[i];
    std::cout << std::left << std::setw(6) << (i + 1) << std::setw(20) << e.ip
              << std::setw(15) << e.total_bytes << std::setw(15) << e.out_bytes
              << std::setw(15) << e.in_bytes << std::fixed
              << std::setprecision(3) << std::setw(10) << e.out_ratio << "\n";
  }
}

void print_https(const std::vector<NodeHttpsEntry> &entries) {
  std::cout << std::left << std::setw(6) << "Rank" << std::setw(20) << "IP"
            << std::setw(15) << "HttpsBytes" << std::setw(15) << "HttpsOut"
            << std::setw(15) << "HttpsIn"
            << "\n";
  std::cout << std::string(71, '-') << "\n";
  for (int i = 0; i < (int)entries.size(); i++) {
    const auto &e = entries[i];
    std::cout << std::left << std::setw(6) << (i + 1) << std::setw(20) << e.ip
              << std::setw(15) << e.https_bytes << std::setw(15) << e.https_out
              << std::setw(15) << e.https_in << "\n";
  }
}
