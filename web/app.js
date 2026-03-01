const API_BASE = "http://127.0.0.1:8000";

// Tab Switching Logic
function switchTab(tabId) {
    // Nav active state
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');

    // Content active state
    document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');

    // Update Title
    const titleText = document.querySelector(`[data-tab="${tabId}"]`).innerText;
    document.getElementById('tab-title').innerText = titleText;
}

function showLoader() {
    document.getElementById('loader').classList.remove('hidden');
}

function hideLoader() {
    document.getElementById('loader').classList.add('hidden');
}

function updateConsole(text) {
    const out = document.getElementById('console-output');
    out.innerText = text;
    // Auto scroll
    out.scrollTop = out.scrollHeight;
}

// Format command array to pretty string for logger
function formatCmdLog(args) {
    return `> ./app ${args.join(' ')}\n\n`;
}

// API Call Wrapper
async function runCommand(baseCmd, paramsArray) {
    const csvPath = document.getElementById('csv-path').value;
    const args = [baseCmd, ...paramsArray];

    showLoader();
    updateConsole(formatCmdLog(args) + "Executing...");

    try {
        const response = await fetch(`${API_BASE}/api/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ args: args, csv_path: csvPath })
        });

        const data = await response.json();

        if (response.ok) {
            updateConsole(formatCmdLog(args) + data.output);
        } else {
            updateConsole(`[ERROR ${response.status}]\n${data.detail}`);
        }
    } catch (error) {
        updateConsole(`[NETWORK ERROR]\n${error.message}`);
    } finally {
        hideLoader();
    }
}

// Specific API call for Visualization
async function runVisualization(ip) {
    const csvPath = document.getElementById('csv-path').value;
    const outFile = 'out/subgraph_edges.csv';
    const args = ['export-subgraph', '--ip', ip, '--out', outFile];

    showLoader();
    updateConsole(formatCmdLog(args) + "Executing C++ subgraph export and generating Python/PyVis graph...");

    // Hide iframe until ready
    document.getElementById('vis-container').classList.add('hidden');
    document.getElementById('vis-frame').src = "about:blank";

    try {
        const response = await fetch(`${API_BASE}/api/visualize`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ args: args, csv_path: csvPath })
        });

        const data = await response.json();

        if (response.ok) {
            updateConsole(formatCmdLog(args) + data.output);
            if (data.html_ready) {
                // Point iframe to the static route serving the generated HTML
                document.getElementById('vis-frame').src = `${API_BASE}/out/subgraph.html?timestamp=${new Date().getTime()}`;
                document.getElementById('vis-container').classList.remove('hidden');
            }
        } else {
            updateConsole(`[ERROR ${response.status}]\n${data.detail}`);
        }
    } catch (error) {
        updateConsole(`[NETWORK ERROR]\n${error.message}`);
    } finally {
        hideLoader();
    }
}
