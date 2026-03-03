#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eval.py — 网络流量分析系统 交互式评测脚本
Interactive Evaluation Script for Network Traffic Analyzer

使用方法: python py/eval.py [--input <csv_path>]
Usage   : python py/eval.py [--input <csv_path>]
"""

import subprocess
import time
import sys
import os

# ─── 配置 ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP         = os.path.join(BASE_DIR, "./app")
DEFAULT_CSV = os.path.join(BASE_DIR, "data/network_data.csv")

# ─── 颜色代码 ─────────────────────────────────────────────────────────────────
R  = "\033[91m"   # Red
G  = "\033[92m"   # Green
Y  = "\033[93m"   # Yellow
B  = "\033[94m"   # Blue
M  = "\033[95m"   # Magenta
C  = "\033[96m"   # Cyan
W  = "\033[97m"   # White
DIM= "\033[2m"
RESET = "\033[0m"
BOLD  = "\033[1m"

# ─── 检查表 ───────────────────────────────────────────────────────────────────
CHECKLIST = {
    1:  "数据读取: CSV 解析与错误行跳过",
    2:  "图构建: 哈希邻接表 + 边归并",
    3:  "全局流量排序 (sort --top K)",
    4:  "HTTPS流量排序 (sort-https --top K)",
    5:  "单向异常筛查 (sort-oneway --threshold T)",
    6:  "最短路径 BFS (path --metric hop)",
    7:  "最低拥塞路径 Dijkstra (path --metric congestion)",
    8:  "双路径对比 (path --metric both)",
    9:  "星型拓扑检测 (stars --min-leaves N)",
    10: "IP段安全规则 (rule iprange --mode deny/allow)",
    11: "子图导出与可视化 (export + graph vis)",
    12: "[扩展] PCAP 提取 + 实时监控大屏",
    13: "[扩展] Web 前端界面演示",
    14: "[扩展] JSON 协议 IPC 演示 (--json flag)",
    15: "全项目性能基准测试 (benchmark all)",
}

# ─── 测试用例配置 ─────────────────────────────────────────────────────────────
TESTS = {
    1: {
        "title": "📂 数据读取 & 图全局统计",
        "desc":  "验证 CSV 解析与图结构构建。输出节点数、边数、会话总数。",
        "cases": [
            {"label": "默认数据集", "args": ["stats"]},
        ],
    },
    2: {
        "title": "📊 全局流量排序 — sort",
        "desc":  "验证 std::partial_sort O(N log K)。输出流量 Top K 节点。",
        "cases": [
            {"label": "Top 5",  "args": ["sort", "--top", "5"]},
            {"label": "Top 10", "args": ["sort", "--top", "10"]},
            {"label": "Top 20", "args": ["sort", "--top", "20"]},
        ],
    },
    3: {
        "title": "🔒 HTTPS 流量排序 — sort-https",
        "desc":  "仅统计 TCP:443 端口流量，验证协议过滤逻辑。",
        "cases": [
            {"label": "Top 5",  "args": ["sort-https", "--top", "5"]},
            {"label": "Top 20", "args": ["sort-https", "--top", "20"]},
        ],
    },
    4: {
        "title": "🚨 单向流量异常筛查 — sort-oneway",
        "desc":  "出向占比超阈值的潜在扫描器/僵尸节点识别。",
        "cases": [
            {"label": "阈值0.9 Top5",  "args": ["sort-oneway", "--threshold", "0.9",  "--top", "5"]},
            {"label": "阈值0.8 Top10", "args": ["sort-oneway", "--threshold", "0.8",  "--top", "10"]},
            {"label": "阈值0.95 Top3", "args": ["sort-oneway", "--threshold", "0.95", "--top", "3"]},
        ],
    },
    5: {
        "title": "🗺️  最短路径搜寻 — path (BFS)",
        "desc":  "广度优先搜索，最小跳数路径。",
        "cases": [
            {"label": "路径A→B (hop)",
             "args": ["path", "--src", "115.156.142.194", "--dst", "18.182.32.116", "--metric", "hop"]},
            {"label": "路径C→D (hop)",
             "args": ["path", "--src", "183.94.22.88",    "--dst", "116.153.60.140",  "--metric", "hop"]},
        ],
    },
    6: {
        "title": "⚡ 最低拥塞路径 — path (Dijkstra)",
        "desc":  "优先队列加速的 Dijkstra，最低拥塞代价路径。",
        "cases": [
            {"label": "路径A→B (congestion)",
             "args": ["path", "--src", "115.156.142.194", "--dst", "18.182.32.116", "--metric", "congestion"]},
            {"label": "路径C→D (congestion)",
             "args": ["path", "--src", "183.94.22.88",    "--dst", "116.153.60.140",  "--metric", "congestion"]},
        ],
    },
    7: {
        "title": "🔀 双路径对比 — path (both)",
        "desc":  "同时运行 BFS 和 Dijkstra，对比两种算法的路径差异。",
        "cases": [
            {"label": "路径A→B (both)",
             "args": ["path", "--src", "115.156.142.194", "--dst", "18.182.32.116", "--metric", "both"]},
            {"label": "路径C→D (both)",
             "args": ["path", "--src", "183.94.22.88",    "--dst", "116.153.60.140",  "--metric", "both"]},
        ],
    },
    8: {
        "title": "⭐ 星型拓扑检测 — stars",
        "desc":  "检测纯叶子节点数 ≥ min-leaves 的中心节点（CDN/网关排查）。",
        "cases": [
            {"label": "min-leaves=5",  "args": ["stars", "--min-leaves", "5"]},
            {"label": "min-leaves=10", "args": ["stars", "--min-leaves", "10"]},
            {"label": "min-leaves=20", "args": ["stars", "--min-leaves", "20"]},
            {"label": "min-leaves=50", "args": ["stars", "--min-leaves", "50"]},
        ],
    },
    9: {
        "title": "🛡️  IP段安全规则 — rule iprange",
        "desc":  "uint32_t 位移掩码算法，检测受控IP对黑名单段的非法通信。",
        "cases": [
            {"label": "DENY模式",
             "args": ["rule", "iprange", "--mode", "deny",
                      "--ip1", "115.156.142.194",
                      "--low", "18.182.32.100", "--high", "18.182.32.200"]},
            {"label": "ALLOW模式",
             "args": ["rule", "iprange", "--mode", "allow",
                      "--ip1", "183.94.22.88",
                      "--low", "183.94.0.0", "--high", "183.94.255.255"]},
        ],
    },
    10: {
        "title": "📤 子图导出 — export",
        "desc":  "BFS 切割局部连通子图并导出 CSV，供可视化引擎消费。",
        "cases": [
            {"label": "导出 115.156.142.194 子图",
             "args": ["export", "--ip", "115.156.142.194"]},
        ],
    },
    11: {
        "title": "🚀 全项目性能基准测试 (Benchmark All)",
        "desc":  "一键运行全部功能并统计各自执行时间，生成性能报告。",
        "cases": [
            {"label": "stats",     "args": ["stats"]},
            {"label": "sort",      "args": ["sort",       "--top", "20"]},
            {"label": "sort-https","args": ["sort-https", "--top", "20"]},
            {"label": "sort-oneway","args":["sort-oneway","--threshold","0.8","--top","20"]},
            {"label": "path (BFS)","args": ["path","--src","115.156.142.194","--dst","18.182.32.116","--metric","hop"]},
            {"label": "path (Dijkstra)","args":["path","--src","115.156.142.194","--dst","18.182.32.116","--metric","congestion"]},
            {"label": "stars",     "args": ["stars",      "--min-leaves", "20"]},
            {"label": "rule",      "args": ["rule","iprange","--mode","deny",
                                            "--ip1","115.156.142.194",
                                            "--low","18.182.32.100","--high","18.182.32.200"]},
        ],
    },
}

# ─── 核心运行函数 ─────────────────────────────────────────────────────────────
def run_case(csv_path: str, args: list, label: str):
    cmd = [APP, "--input", csv_path] + args
    print(f"\n{DIM}  $ {' '.join(cmd)}{RESET}")
    print(f"  {DIM}{'─'*60}{RESET}")

    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        elapsed = time.perf_counter() - t0
        output = result.stdout.strip()
        if result.returncode != 0:
            output += "\n" + result.stderr.strip()
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - t0
        output = f"{R}[TIMEOUT] 超过 30 秒未返回{RESET}"
    except FileNotFoundError:
        elapsed = time.perf_counter() - t0
        output = f"{R}[ERROR] 找不到 ./app 二进制，请先运行 make{RESET}"

    # 缩进输出
    for line in output.split("\n"):
        print(f"  {line}")

    color = G if elapsed < 0.5 else (Y if elapsed < 2.0 else R)
    print(f"\n  {color}⏱  执行时间: {elapsed*1000:.2f} ms  ({elapsed:.4f} s){RESET}")
    return elapsed

def run_benchmark(csv_path: str):
    """全项目基准测试模式 (选项11)"""
    test = TESTS[11]
    print(f"\n{BOLD}{M}{'═'*64}{RESET}")
    print(f"{BOLD}{M}  {test['title']}{RESET}")
    print(f"{M}  {test['desc']}{RESET}")
    print(f"{BOLD}{M}{'═'*64}{RESET}")

    results = []
    for case in test["cases"]:
        print(f"\n{C}{BOLD}  [{case['label']}]{RESET}")
        t = run_case(csv_path, case["args"], case["label"])
        results.append((case["label"], t))

    # 汇总报告
    total = sum(t for _, t in results)
    print(f"\n{BOLD}{B}{'═'*64}{RESET}")
    print(f"{BOLD}{B}  性能汇总报告 / Performance Summary{RESET}")
    print(f"{B}  {'功能':<30} {'耗时 (ms)':>12}{RESET}")
    print(f"{B}  {'─'*46}{RESET}")
    for label, t in results:
        color = G if t < 0.5 else (Y if t < 2.0 else R)
        print(f"  {label:<30} {color}{t*1000:>10.2f} ms{RESET}")
    print(f"{B}  {'─'*46}{RESET}")
    print(f"  {'总计 / Total':<30} {BOLD}{total*1000:>10.2f} ms{RESET}")
    print(f"{BOLD}{B}{'═'*64}{RESET}\n")

def run_menu_item(choice: int, csv_path: str):
    if choice == 11:
        run_benchmark(csv_path)
        return

    if choice not in TESTS:
        print(f"{R}  无效选项！{RESET}")
        return

    test = TESTS[choice]
    print(f"\n{BOLD}{C}{'═'*64}{RESET}")
    print(f"{BOLD}{C}  {test['title']}{RESET}")
    print(f"{C}  {test['desc']}{RESET}")
    print(f"{BOLD}{C}{'═'*64}{RESET}")

    cases = test["cases"]
    if len(cases) == 1:
        run_case(csv_path, cases[0]["args"], cases[0]["label"])
    else:
        print(f"\n  选择测试样例 (直接回车运行全部):")
        for i, c in enumerate(cases, 1):
            print(f"    {Y}{i}{RESET}. {c['label']}")
        sel = input(f"\n  > ").strip()
        if sel == "":
            for c in cases:
                print(f"\n{Y}  ▶ {c['label']}{RESET}")
                run_case(csv_path, c["args"], c["label"])
        elif sel.isdigit() and 1 <= int(sel) <= len(cases):
            c = cases[int(sel)-1]
            run_case(csv_path, c["args"], c["label"])
        else:
            print(f"{R}  无效选择{RESET}")

# ─── 检查表与主菜单 ───────────────────────────────────────────────────────────
def print_checklist(completed: set):
    print(f"\n{BOLD}{W}  ╔══════════ 验收检查表 ════════════╗{RESET}")
    for k, v in CHECKLIST.items():
        mark = f"{G}✓{RESET}" if k in completed else f"{DIM}○{RESET}"
        item_str = f"{k:>2}. {v}"
        mapped = {
            1: [1], 2: [1],          # stats covers items 1&2
            3: [2], 4: [3], 5: [4],
            6: [5], 7: [6], 8: [7],
            9: [8], 10: [9], 11: [10],
        }.get(k, [])
        # if any test menu item in mapped was run
        done = any(m in completed for m in mapped)
        mark = f"{G}✓{RESET}" if done else f"{DIM}○{RESET}"
        print(f"  {mark} {item_str}")
    print(f"{BOLD}{W}  ╚══════════════════════════════════╝{RESET}")

def print_menu(csv_path: str):
    print(f"\n{BOLD}{B}{'═'*64}{RESET}")
    print(f"{BOLD}{B}  🌐 网络流量分析系统 — 交互式评测脚本{RESET}")
    print(f"{BOLD}{B}  Network Traffic Analyzer — Evaluation Script{RESET}")
    print(f"{B}  数据源: {csv_path}{RESET}")
    print(f"{BOLD}{B}{'═'*64}{RESET}")
    
    menu_items = [
        (1,  "📂", "数据读取 & 图全局统计"),
        (2,  "📊", "全局流量排序 (sort)"),
        (3,  "🔒", "HTTPS 流量排序 (sort-https)"),
        (4,  "🚨", "单向异常筛查 (sort-oneway)"),
        (5,  "🗺️ ", "最短路径 BFS (path --metric hop)"),
        (6,  "⚡", "最低拥塞路径 Dijkstra (path --metric congestion)"),
        (7,  "🔀", "双路径对比 (path --metric both)"),
        (8,  "⭐", "星型拓扑检测 (stars)"),
        (9,  "🛡️ ", "IP段安全规则 (rule iprange)"),
        (10, "📤", "子图导出 (export)"),
        (11, "🚀", "全项目性能基准测试 (Benchmark All)"),
    ]
    
    print()
    for num, icon, title in menu_items:
        print(f"  {Y}{num:>2}.{RESET} {icon} {BOLD}{title}{RESET}")
        if num in TESTS and num != 11:
            for c in TESTS[num]["cases"]:
                cmd_preview = " ".join(["./app"] + c["args"])
                print(f"       {DIM}  [{c['label']}] {cmd_preview}{RESET}")
        print()
    
    print(f"  {DIM}c{RESET}  — 查看验收检查表")
    print(f"  {DIM}q{RESET}  — 退出\n")

def main():
    # 解析命令行参数
    csv_path = DEFAULT_CSV
    if "--input" in sys.argv:
        idx = sys.argv.index("--input")
        if idx + 1 < len(sys.argv):
            csv_path = sys.argv[idx + 1]

    # 检查二进制是否存在
    os.chdir(BASE_DIR)
    if not os.path.exists(APP):
        print(f"{R}[!] 找不到 ./app 二进制，正在自动编译...{RESET}")
        os.system("make")
        if not os.path.exists(APP):
            print(f"{R}[!] 编译失败，请手动运行 make{RESET}")
            sys.exit(1)

    if not os.path.exists(csv_path):
        print(f"{R}[!] CSV 数据文件不存在: {csv_path}{RESET}")
        sys.exit(1)

    completed = set()

    while True:
        print_menu(csv_path)
        raw = input(f"  请输入选项 / Enter option: ").strip().lower()

        if raw == "q":
            print(f"\n{G}  评测结束，已运行 {len(completed)} 个测试项目。再见！{RESET}\n")
            break
        elif raw == "c":
            print_checklist(completed)
        elif raw.isdigit() and 1 <= int(raw) <= 11:
            choice = int(raw)
            run_menu_item(choice, csv_path)
            completed.add(choice)
            input(f"\n  {DIM}按 Enter 返回主菜单...{RESET}")
        else:
            print(f"{R}  无效输入，请输入 1-11、c 或 q{RESET}")

if __name__ == "__main__":
    main()
