const API_BASE = "http://127.0.0.1:8000";

// Tab Switching Logic
function switchTab(tabId) {
    // Nav active state
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const activeNav = document.querySelector(`[data-tab="${tabId}"]`);
    activeNav.classList.add('active');

    // Content active state
    document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');

    // Update Title with bilingual text
    const enTextNode = activeNav.querySelector('.nav-label').childNodes[0];
    const enText = enTextNode ? enTextNode.textContent.trim() : '';
    const cnNode = activeNav.querySelector('.nav-cn');
    const cnText = cnNode ? cnNode.innerText.trim() : '';

    document.getElementById('tab-title').innerHTML = `${enText} <span style="font-size: 0.85em; color: var(--text-secondary); font-weight: normal;">/ ${cnText}</span>`;
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
    updateConsole(formatCmdLog(args) + "Executing... / 正在执行...");

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
        updateConsole(`[NETWORK ERROR / 网络错误]\n${error.message}`);
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
    updateConsole(formatCmdLog(args) + "Executing C++ subgraph export and generating Python/PyVis graph...\n正在导出 C++ 连通子图并生成 Python 交互图表...");

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
        updateConsole(`[NETWORK ERROR / 网络错误]\n${error.message}`);
    } finally {
        hideLoader();
    }
}

// Live Dashboard Logic
let liveInterval = null;

async function pollLiveStats(pcapFile) {
    try {
        const response = await fetch(`${API_BASE}/api/live`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pcap_file: pcapFile })
        });
        const data = await response.json();

        if (response.ok) {
            updateConsole(`[LIVE UPDATE / 实时刷新]\n${data.output}`);
        } else {
            updateConsole(`[LIVE ERROR]\n${data.detail}`);
            toggleLiveDashboard(); // Stop on error
        }
    } catch (e) {
        updateConsole(`[LIVE NETWORK ERROR]\n${e.message}`);
        toggleLiveDashboard(); // Stop on error
    }
}

function toggleLiveDashboard() {
    const btnText = document.getElementById('live-btn-text');
    const pcapFile = document.getElementById('live-pcap').value;

    if (liveInterval) {
        // Stop live
        clearInterval(liveInterval);
        liveInterval = null;
        btnText.innerHTML = 'Start Live <span>开启监控</span>';
        updateConsole("Live Dashboard stopped. / 实时监控已停止。");
    } else {
        // Start live
        updateConsole(`Starting Live Dashboard for ${pcapFile}... / 正在启动 ${pcapFile} 的实时监控...`);
        btnText.innerHTML = '<i class="fa-solid fa-stop"></i> Stop Live <span>停止监控</span>';

        // Initial poll
        pollLiveStats(pcapFile);

        // Poll every 5 seconds
        liveInterval = setInterval(() => {
            pollLiveStats(pcapFile);
        }, 5000);
    }
}
