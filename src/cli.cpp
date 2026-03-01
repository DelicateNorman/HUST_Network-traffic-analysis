#include "cli.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

/**
 * cli.cpp
 * Command-line argument parsing.
 * Supports global options anywhere and subcommands.
 */

void print_help() {
  std::cout
      << "Usage: app <command> [options]\n\n"
         "Commands:\n"
         "  sort             Sort nodes by total traffic\n"
         "  sort-https       Sort nodes by HTTPS traffic\n"
         "  sort-oneway      List nodes where outbound ratio > threshold\n"
         "  path             Find path between two nodes\n"
         "  stars            Detect star topologies\n"
         "  rule iprange     Apply IP range security rule\n"
         "  stats            Print graph statistics\n"
         "  export-subgraph  Export connected subgraph to CSV\n\n"
         "Global Options:\n"
         "  --input <path>   Input CSV file (default: data/network_data.csv)\n"
         "  --dump N         Print first N raw session records\n"
         "  --show-node <ip> Show adjacency info for an IP\n\n"
         "Sort Options:\n"
         "  --top N          Output top N nodes (default: 20)\n\n"
         "Sort-oneway Options:\n"
         "  --threshold F    Out-ratio threshold (default: 0.8)\n\n"
         "Path Options:\n"
         "  --src <ip>       Source IP\n"
         "  --dst <ip>       Destination IP\n"
         "  --metric <m>     'hop' or 'congestion' (default: hop)\n\n"
         "Stars Options:\n"
         "  --min-leaves N   Minimum leaf count (default: 20)\n\n"
         "Rule iprange Options:\n"
         "  --mode deny|allow\n"
         "  --ip1 <ip>       Controlled IP\n"
         "  --low <ip>       Range lower bound\n"
         "  --high <ip>      Range upper bound\n\n"
         "Export-subgraph Options:\n"
         "  --ip <ip>        IP whose component to export\n"
         "  --out <path>     Output CSV file (default: "
         "out/subgraph_edges.csv)\n\n"
         "Exit Codes:\n"
         "  0  Success\n"
         "  2  Argument error\n"
         "  3  File I/O error\n"
         "  4  Node not found\n"
         "  5  Path does not exist\n";
}

CliOptions parse_args(int argc, char *argv[]) {
  CliOptions opts;
  if (argc < 2) {
    print_help();
    std::exit(2);
  }

  bool cmd_found = false;
  int i = 1;

  while (i < argc) {
    std::string arg = argv[i++];
    if (arg == "--help" || arg == "-h") {
      print_help();
      std::exit(0);
    } else if (arg == "--input" && i < argc)
      opts.input_file = argv[i++];
    else if (arg == "--top" && i < argc)
      opts.top_k = std::atoi(argv[i++]);
    else if (arg == "--threshold" && i < argc)
      opts.threshold = std::atof(argv[i++]);
    else if (arg == "--src" && i < argc)
      opts.src_ip = argv[i++];
    else if (arg == "--dst" && i < argc)
      opts.dst_ip = argv[i++];
    else if (arg == "--metric" && i < argc)
      opts.metric = argv[i++];
    else if (arg == "--min-leaves" && i < argc)
      opts.min_leaves = std::atoi(argv[i++]);
    else if (arg == "--mode" && i < argc)
      opts.rule_mode = argv[i++];
    else if (arg == "--ip1" && i < argc)
      opts.ip1 = argv[i++];
    else if (arg == "--low" && i < argc)
      opts.ip_low = argv[i++];
    else if (arg == "--high" && i < argc)
      opts.ip_high = argv[i++];
    else if (arg == "--ip" && i < argc)
      opts.export_ip = argv[i++];
    else if (arg == "--out" && i < argc)
      opts.out_file = argv[i++];
    else if (arg == "--dump" && i < argc)
      opts.dump_n = std::atoi(argv[i++]);
    else if (arg == "--show-node" && i < argc)
      opts.show_node_ip = argv[i++];
    else if (arg.size() > 2 && arg.substr(0, 2) == "--") {
      std::cerr << "[ERROR] Unknown option: " << arg << "\n";
      std::cerr << "Use --help to see available options.\n";
      std::exit(2);
    } else {
      // Positional argument -> Subcommand
      if (!cmd_found) {
        opts.command = arg;
        cmd_found = true;
        // Handle "rule iprange"
        if (opts.command == "rule" && i < argc) {
          std::string sub = argv[i];
          if (sub == "iprange") {
            opts.command = "rule-iprange";
            i++;
          }
        }
      } else {
        std::cerr << "[ERROR] Unknown argument: " << arg << "\n";
        std::exit(2);
      }
    }
  }

  if (opts.command.empty()) {
    std::cerr << "[ERROR] No command specified.\n";
    print_help();
    std::exit(2);
  }

  return opts;
}
