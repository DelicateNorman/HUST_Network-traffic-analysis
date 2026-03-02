#include "cli.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

/**
 * @file cli.cpp
 * @brief Command-line argument parsing and configuration.
 *
 * Provides functions to parse command-line arguments into a structured
 * CliOptions object, supporting global options placed anywhere and commands.
 */

/**
 * @brief Prints the bilingual help message to standard output.
 * 打印双语命令行帮助信息。
 */
void print_help() {
  std::cout
      << "Usage / 用法: app <command> [options]\n\n"
         "Commands / 可用命令:\n"
         "  sort             Sort nodes by total traffic / 按总流量对节点排序\n"
         "  sort-https       Sort nodes by HTTPS traffic / 按 HTTPS 流量排序\n"
         "  sort-oneway      List one-way anomaly nodes / "
         "列出单向异常流量节点(扫描器)\n"
         "  path             Find path between two nodes / 寻找两节点间的路径\n"
         "  stars            Detect star topologies / 检测星型拓扑结构\n"
         "  rule iprange     Apply IP range security rule / 应用 IP "
         "范围安全规则\n"
         "  stats            Print graph statistics / 打印全图统计信息\n"
         "  export-subgraph  Export connected subgraph / "
         "导出连通子图以供可视化\n\n"
         "Global Options / 全局选项:\n"
         "  --input <path>   Input CSV file / 输入待分析的CSV文件路径 "
         "(default: data/network_data.csv)\n"
         "  --dump N         Print first N raw session records / 打印前 N "
         "条原始会话记录\n"
         "  --show-node <ip> Show adjacency info for an IP / 显示特定 IP "
         "的邻接信息\n\n"
         "Sort Options / 排序选项:\n"
         "  --top N          Output top N nodes / 输出前 N 个节点 (default: "
         "20)\n\n"
         "Sort-oneway Options / 单向异常选项:\n"
         "  --threshold F    Out-ratio threshold / 出向占比阈值 (default: "
         "0.8)\n\n"
         "Path Options / 路径选项:\n"
         "  --src <ip>       Source IP / 源 IP\n"
         "  --dst <ip>       Destination IP / 目的 IP\n"
         "  --metric <m>     'hop' (BFS) or 'congestion' (Dijkstra) / 距离指标 "
         "(default: hop)\n\n"
         "Stars Options / 星型网络选项:\n"
         "  --min-leaves N   Minimum leaf count / 最小叶子节点数量 (default: "
         "20)\n\n"
         "Rule iprange Options / IP规则选项:\n"
         "  --mode deny|allow\n"
         "  --ip1 <ip>       Controlled IP / 受控的主机 IP\n"
         "  --low <ip>       Range lower bound / 范围下界\n"
         "  --high <ip>      Range upper bound / 范围上界\n\n"
         "Export-subgraph Options / 导出子图选项:\n"
         "  --ip <ip>        Target IP / 目标提取 IP\n"
         "  --out <path>     Output CSV file / 导出文件 (default: "
         "out/subgraph_edges.csv)\n\n"
         "Exit Codes / 退出码:\n"
         "  0  Success / 成功\n"
         "  2  Argument error / 参数错误\n"
         "  3  File I/O error / 文件读写错误\n"
         "  4  Node not found / 节点未找到\n"
         "  5  Path does not exist / 路径不存在\n";
}

/**
 * @brief Parses command line arguments and populates the CliOptions structure.
 *
 * Includes robust handling for global options placement and nested subcommands
 * like 'rule iprange'. Exits the program on unknown or malformed arguments.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return CliOptions The parsed options ready to be used by the main
 * dispatcher.
 */
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
    else if (arg == "--json")
      opts.json_output = true;
    else if (arg.size() > 2 && arg.substr(0, 2) == "--") {
      std::cerr << "[ERROR] Unknown option / 未知选项: " << arg << "\n";
      std::cerr
          << "Use --help to see available options. / 使用 --help 查看帮助\n";
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
        std::cerr << "[ERROR] Unknown argument / 未知参数: " << arg << "\n";
        std::exit(2);
      }
    }
  }

  if (opts.command.empty()) {
    std::cerr << "[ERROR] No command specified. / 未指定要执行的命令。\n";
    print_help();
    std::exit(2);
  }

  return opts;
}
