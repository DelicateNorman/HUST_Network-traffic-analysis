#!/usr/bin/env python3
"""
gui.py - FR-8: Python Tkinter GUI for the Network Traffic Analyzer.
Calls ./app subcommands via subprocess and displays results.
Usage: python3 py/gui.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import threading
import os
import sys

APP_BINARY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'app')
DEFAULT_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'data', 'network_data.csv')

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analyzer")
        self.geometry("1000x700")
        self.configure(bg="#1a1a2e")
        self.resizable(True, True)

        self.csv_var     = tk.StringVar(value=DEFAULT_CSV)
        self.topk_var    = tk.StringVar(value="20")
        self.thresh_var  = tk.StringVar(value="0.8")
        self.src_var     = tk.StringVar()
        self.dst_var     = tk.StringVar()
        self.metric_var  = tk.StringVar(value="both")
        self.minleaf_var = tk.StringVar(value="20")
        self.mode_var    = tk.StringVar(value="deny")
        self.ip1_var     = tk.StringVar()
        self.low_var     = tk.StringVar()
        self.high_var    = tk.StringVar()
        self.expip_var   = tk.StringVar()

        self._build_ui()

    def _style(self):
        s = ttk.Style()
        s.theme_use('clam')
        s.configure('TFrame',     background='#1a1a2e')
        s.configure('TLabel',     background='#1a1a2e', foreground='#e0e0e0', font=('Consolas', 10))
        s.configure('TButton',    background='#16213e', foreground='#00d4ff',
                    font=('Consolas', 10, 'bold'), padding=6)
        s.map('TButton',          background=[('active', '#0f3460')])
        s.configure('TEntry',     fieldbackground='#16213e', foreground='#e0e0e0',
                    insertcolor='white')
        s.configure('TLabelframe',      background='#1a1a2e', foreground='#00d4ff')
        s.configure('TLabelframe.Label', background='#1a1a2e', foreground='#00d4ff',
                    font=('Consolas', 10, 'bold'))

    def _build_ui(self):
        self._style()

        main = ttk.Frame(self)
        main.pack(fill='both', expand=True, padx=12, pady=12)

        # Top: file selector
        top = ttk.LabelFrame(main, text="Data File")
        top.pack(fill='x', pady=(0, 8))
        ttk.Label(top, text="CSV:").pack(side='left', padx=4)
        ttk.Entry(top, textvariable=self.csv_var, width=60).pack(side='left', padx=4)
        ttk.Button(top, text="Browse", command=self._browse).pack(side='left', padx=4)

        # Middle: left panel (controls) + right panel (output)
        mid = ttk.Frame(main)
        mid.pack(fill='both', expand=True)

        ctrl = ttk.Frame(mid)
        ctrl.pack(side='left', fill='y', padx=(0, 8))

        out_frame = ttk.LabelFrame(mid, text="Output")
        out_frame.pack(side='left', fill='both', expand=True)
        self.output = scrolledtext.ScrolledText(
            out_frame, bg='#0d1117', fg='#00ff88', font=('Consolas', 10),
            insertbackground='white', wrap='word')
        self.output.pack(fill='both', expand=True, padx=4, pady=4)

        self._build_controls(ctrl)

    def _build_controls(self, parent):
        # Stats
        f = ttk.LabelFrame(parent, text="Graph Stats")
        f.pack(fill='x', pady=4)
        ttk.Button(f, text="stats", command=lambda: self._run(['stats'])).pack(fill='x', padx=4, pady=2)

        # Sort
        f = ttk.LabelFrame(parent, text="Sort (Top N)")
        f.pack(fill='x', pady=4)
        row = ttk.Frame(f); row.pack(fill='x', padx=4)
        ttk.Label(row, text="Top K:").pack(side='left')
        ttk.Entry(row, textvariable=self.topk_var, width=6).pack(side='left', padx=4)
        ttk.Button(f, text="sort (all traffic)",
                   command=lambda: self._run(['sort','--top', self.topk_var.get()])
                   ).pack(fill='x', padx=4, pady=2)
        ttk.Button(f, text="sort-https",
                   command=lambda: self._run(['sort-https','--top', self.topk_var.get()])
                   ).pack(fill='x', padx=4, pady=2)

        # One-way
        f2 = ttk.LabelFrame(parent, text="One-way Nodes")
        f2.pack(fill='x', pady=4)
        row2 = ttk.Frame(f2); row2.pack(fill='x', padx=4)
        ttk.Label(row2, text="Threshold:").pack(side='left')
        ttk.Entry(row2, textvariable=self.thresh_var, width=6).pack(side='left', padx=4)
        ttk.Button(f2, text="sort-oneway",
                   command=lambda: self._run(['sort-oneway','--threshold', self.thresh_var.get(),
                                             '--top', self.topk_var.get()])
                   ).pack(fill='x', padx=4, pady=2)

        # Path
        f3 = ttk.LabelFrame(parent, text="Path Finding")
        f3.pack(fill='x', pady=4)
        for lbl, var in [("Src IP:", self.src_var), ("Dst IP:", self.dst_var)]:
            row = ttk.Frame(f3); row.pack(fill='x', padx=4)
            ttk.Label(row, text=lbl, width=8).pack(side='left')
            ttk.Entry(row, textvariable=var, width=18).pack(side='left', padx=2)
        metric_row = ttk.Frame(f3); metric_row.pack(fill='x', padx=4)
        ttk.Label(metric_row, text="Metric:").pack(side='left')
        for m in ("hop", "congestion", "both"):
            ttk.Radiobutton(metric_row, text=m, variable=self.metric_var, value=m).pack(side='left')
        ttk.Button(f3, text="Find Path",
                   command=lambda: self._run(['path','--src', self.src_var.get(),
                                             '--dst', self.dst_var.get(),
                                             '--metric', self.metric_var.get()])
                   ).pack(fill='x', padx=4, pady=2)

        # Stars
        f4 = ttk.LabelFrame(parent, text="Star Topology")
        f4.pack(fill='x', pady=4)
        row4 = ttk.Frame(f4); row4.pack(fill='x', padx=4)
        ttk.Label(row4, text="Min Leaves:").pack(side='left')
        ttk.Entry(row4, textvariable=self.minleaf_var, width=6).pack(side='left', padx=4)
        ttk.Button(f4, text="stars",
                   command=lambda: self._run(['stars','--min-leaves', self.minleaf_var.get()])
                   ).pack(fill='x', padx=4, pady=2)

        # Security rule
        f5 = ttk.LabelFrame(parent, text="IP Range Rule")
        f5.pack(fill='x', pady=4)
        for lbl, var in [("IP1:", self.ip1_var), ("Low:", self.low_var), ("High:", self.high_var)]:
            row = ttk.Frame(f5); row.pack(fill='x', padx=4)
            ttk.Label(row, text=lbl, width=6).pack(side='left')
            ttk.Entry(row, textvariable=var, width=18).pack(side='left', padx=2)
        mr = ttk.Frame(f5); mr.pack(fill='x', padx=4)
        ttk.Label(mr, text="Mode:").pack(side='left')
        for m in ("deny", "allow"):
            ttk.Radiobutton(mr, text=m, variable=self.mode_var, value=m).pack(side='left')
        ttk.Button(f5, text="Apply Rule",
                   command=lambda: self._run(['rule','iprange','--mode', self.mode_var.get(),
                                             '--ip1', self.ip1_var.get(),
                                             '--low', self.low_var.get(),
                                             '--high', self.high_var.get()])
                   ).pack(fill='x', padx=4, pady=2)

        # Export subgraph
        f6 = ttk.LabelFrame(parent, text="Export Subgraph")
        f6.pack(fill='x', pady=4)
        row6 = ttk.Frame(f6); row6.pack(fill='x', padx=4)
        ttk.Label(row6, text="IP:").pack(side='left')
        ttk.Entry(row6, textvariable=self.expip_var, width=18).pack(side='left', padx=2)
        ttk.Button(f6, text="Export & Visualize",
                   command=self._export_and_visualize
                   ).pack(fill='x', padx=4, pady=2)

    def _browse(self):
        path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("All", "*.*")])
        if path:
            self.csv_var.set(path)

    def _run(self, args):
        cmd = [APP_BINARY, '--input', self.csv_var.get()] + args
        self.output.delete('1.0', 'end')
        self.output.insert('end', f"$ {' '.join(cmd)}\n\n")
        self.output.update()
        threading.Thread(target=self._exec, args=(cmd,), daemon=True).start()

    def _exec(self, cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            out = result.stdout + (result.stderr if result.stderr else "")
        except FileNotFoundError:
            out = f"[ERROR] Binary not found: {APP_BINARY}\nRun 'make' first.\n"
        except subprocess.TimeoutExpired:
            out = "[ERROR] Command timed out\n"
        except Exception as e:
            out = f"[ERROR] {e}\n"
        self.output.after(0, lambda: self._append(out))

    def _append(self, text):
        self.output.insert('end', text)
        self.output.see('end')

    def _export_and_visualize(self):
        ip = self.expip_var.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return
        out_csv  = os.path.join(os.path.dirname(APP_BINARY), 'out', 'subgraph_edges.csv')
        out_html = os.path.join(os.path.dirname(APP_BINARY), 'out', 'subgraph.html')
        self._run(['export-subgraph', '--ip', ip, '--out', out_csv])
        # After export, run visualize
        def _vis():
            import time; time.sleep(2)  # wait for export to finish
            vis_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'visualize_subgraph.py')
            subprocess.Popen([sys.executable, vis_script,
                             '--edges', out_csv, '--out', out_html])
        threading.Thread(target=_vis, daemon=True).start()

if __name__ == '__main__':
    app = App()
    app.mainloop()
