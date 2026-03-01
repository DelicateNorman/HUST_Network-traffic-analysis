#pragma once
#include <string>
#include <vector>

/**
 * cli.h
 * CLI argument parsing and command dispatch.
 * Supports subcommands: sort, sort-https, sort-oneway, path, stars, rule,
 * stats, export-subgraph, load
 */

struct CliOptions {
  std::string command; ///< subcommand name
  std::string input_file = "data/network_data.csv";

  // sort / sort-https / sort-oneway
  int top_k = 20;
  double threshold = 0.8;

  // path
  std::string src_ip;
  std::string dst_ip;
  std::string metric = "hop"; ///< "hop" or "congestion"

  // stars
  int min_leaves = 20;

  // rule iprange
  std::string rule_mode; ///< "deny" or "allow"
  std::string ip1;
  std::string ip_low;
  std::string ip_high;

  // export-subgraph
  std::string export_ip;
  std::string out_file = "out/subgraph_edges.csv";

  // dump N raw records
  int dump_n = 0;

  // show-node
  std::string show_node_ip;
};

/**
 * Parse command line arguments into CliOptions.
 * Prints usage and exits(2) on error.
 */
CliOptions parse_args(int argc, char *argv[]);

/// Print usage/help to stdout
void print_help();
