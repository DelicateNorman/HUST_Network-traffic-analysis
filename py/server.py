import os
import sys
import subprocess
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Network Traffic Analyzer API")

# Absolute path to the ./app binary (relative to this script's parent dir)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_BIN  = os.path.join(BASE_DIR, 'app')
DEF_CSV  = os.path.join(BASE_DIR, 'data', 'network_data.csv')
OUT_DIR  = os.path.join(BASE_DIR, 'out')
WEB_DIR  = os.path.join(BASE_DIR, 'web')

class CommandRequest(BaseModel):
    args: list[str]
    csv_path: str = DEF_CSV

class LiveRequest(BaseModel):
    pcap_file: str

def run_cli_cmd(args: list[str], csv_path: str) -> str:
    cmd = [APP_BIN, '--input', csv_path] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out = result.stdout
        if result.stderr:
            out += f"\n[STDERR]\n{result.stderr}"
        return out
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Binary not found: {APP_BIN}. Please run `make` first.")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Command timed out (>30s).")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/run")
def api_run_command(req: CommandRequest):
    output = run_cli_cmd(req.args, req.csv_path)
    # Check if the output is JSON (from the new --json flag)
    try:
        import json
        json_data = json.loads(output)
        return {"type": "json", "data": json_data}
    except Exception:
        return {"type": "text", "output": output}

@app.post("/api/visualize")
def api_visualize(req: CommandRequest):
    # args: ['export-subgraph', '--ip', ip, '--out', edge_file]
    output = run_cli_cmd(req.args, req.csv_path)
    
    # After C++ export, run python visualization
    edge_file = None
    for i, a in enumerate(req.args):
        if a == '--out' and i + 1 < len(req.args):
            edge_file = req.args[i+1]
            break
            
    if not edge_file:
        raise HTTPException(status_code=400, detail="--out edge file path missing in args")
        
    node_file = edge_file.replace(".csv", "_nodes.csv")
    out_html = os.path.join(OUT_DIR, 'subgraph.html')
    vis_script = os.path.join(BASE_DIR, 'py', 'visualize_subgraph.py')
    
    try:
        result = subprocess.run([sys.executable, vis_script,
                                 '--edges', edge_file, 
                                 '--nodes', node_file, 
                                 '--out', out_html],
                                capture_output=True, text=True)
        if result.returncode != 0:
             return {"output": output + "\n[VISUALIZATION ERROR]\n" + result.stderr, "html_ready": False}
             
        # Just return the output text. The frontend can serve the HTML file directly.
        return {"output": output + "\n" + result.stdout + "Enhanced 'Bloom' Visualization ready!", "html_ready": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Visualization failed: {e}")

# Live Dashboard state caching
live_state = {
    "last_size": 0
}

@app.post("/api/live")
def api_live_dashboard(req: LiveRequest):
    import time, json
    pcap_path = req.pcap_file
    csv_live_path = os.path.join(BASE_DIR, 'data', 'live_data.csv')
    
    # Check if pcap exists
    if not os.path.exists(pcap_path):
        return {"type": "text", "output": f"[!] Waiting for PCAP file: {pcap_path} ..."}
        
    current_size = os.path.getsize(pcap_path)
    
    if current_size > live_state["last_size"]:
        # Convert PCAP to CSV first
        try:
            sys.path.append(os.path.join(BASE_DIR, 'py'))
            import realtime_dashboard
            realtime_dashboard.fast_convert(pcap_path, csv_live_path)
        except Exception as e:
            return {"type": "text", "output": f"[CONVERSION ERROR / 转换失败] {e}"}

        # Run C++ Analyzers
        try:
            oneway_json_str = run_cli_cmd(["sort-oneway", "--threshold", "0.8", "--top", "3", "--json"], csv_live_path)
            oneway_data = json.loads(oneway_json_str)
            
            top_json_str = run_cli_cmd(["sort", "--top", "5", "--json"], csv_live_path)
            top_data = json.loads(top_json_str)

            # SUCCESS: only now update last_size
            live_state["last_size"] = current_size
            
            live_payload = {
                "type": "live",
                "pcap_size_kb": current_size / 1024,
                "oneway": oneway_data,
                "top_nodes": top_data,
                "time": time.strftime('%H:%M:%S')
            }
            return {"type": "json", "data": live_payload}
        except Exception as e:
            return {"type": "text", "output": f"[ANALYSIS ERROR / 分析失败] {e}"}
        
    else:
        return {"type": "text", "output": f"[{time.strftime('%H:%M:%S')}] No new packets detected. Listening... (file: {current_size/1024:.1f}KB / last: {live_state['last_size']/1024:.1f}KB)"}

@app.get("/api/live/reset")
def api_live_reset():
    live_state["last_size"] = 0
    return {"status": "reset", "last_size": 0}

# Mount out directory to serve subgraph.html
app.mount("/out", StaticFiles(directory=OUT_DIR), name="out")

# Mount web directory to serve frontend assets
app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")

@app.get("/", response_class=HTMLResponse)
def read_root():
    index_path = os.path.join(WEB_DIR, 'index.html')
    if os.path.exists(index_path):
        with open(index_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "<h1>Web frontend not found</h1>"

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
