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

    // Check if the text contains table-like structures (e.g. from sort or anomaly commands)
    if (text.includes('=== Top') || text.includes('=== Nodes with') || text.includes('-------------------------------------')) {
        out.innerHTML = parseTextToHTML(text);
    } else {
        out.innerText = text;
    }

    // Auto scroll
    out.scrollTop = out.scrollHeight;
}

// Advanced Parser: Converts C++ CLI tabular output into sleek HTML tables
function parseTextToHTML(rawText) {
    const lines = rawText.split('\n');
    let html = '';
    let inTable = false;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // Match table headers
        // Since C++ prints bilingual: "Rank  IP  TotalBytes..." and then "排名 IP地址 总流量..."
        if (line.includes('Rank') && line.includes('IP') && line.includes('TotalBytes')) {
            if (!inTable) {
                html += '<div class="table-container fade-up"><table class="data-table">';
                inTable = true;
            }
            html += '<thead><tr><th>Rank</th><th>IP Address</th><th>Total Bytes</th><th>Out Bytes</th><th>In Bytes</th><th>Out Ratio</th></tr></thead><tbody>';
            continue;
        }

        // Skip the Chinese header row which comes immediately after
        if (inTable && line.includes('排名') && line.includes('IP地址')) {
            continue;
        }

        // Skip Dashed lines in table
        if (inTable && line.startsWith('-----')) {
            continue;
        }

        // Match table data rows (e.g., 1 115.156.142.194 12345 1000 11345 0.08)
        const rowMatch = line.match(/^(\d+)\s+([0-9\.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([0-9\.]+)/);
        if (inTable && rowMatch) {
            html += `<tr>
                <td>${rowMatch[1]}</td>
                <td class="ip-cell">${rowMatch[2]}</td>
                <td>${parseInt(rowMatch[3]).toLocaleString()}</td>
                <td>${parseInt(rowMatch[4]).toLocaleString()}</td>
                <td>${parseInt(rowMatch[5]).toLocaleString()}</td>
                <td><span class="ratio-badge ratio-${getRatioClass(parseFloat(rowMatch[6]))}">${rowMatch[6]}</span></td>
            </tr>`;
            continue;
        }

        // End of table detection
        if (inTable && line === '') {
            html += '</tbody></table></div>';
            inTable = false;
            continue;
        }

        // Highlight Headers (=== Title ===)
        const titleMatch = line.match(/^===(.+)===$/);
        if (titleMatch && !inTable) {
            html += `<h4 class="console-title">${titleMatch[1].trim()}</h4>`;
            continue;
        }

        // Normal text
        if (!inTable && line !== '') {
            // escape html
            const safeLine = line.replace(/</g, "&lt;").replace(/>/g, "&gt;");
            // Colorize specific words
            const colorized = safeLine
                .replace(/(\[ERROR.*?\])/g, '<span class="text-red">$1</span>')
                .replace(/(\[WARN.*?\])/g, '<span class="text-yellow">$1</span>')
                .replace(/(Loaded \d+ sessions)/g, '<span class="text-green">$1</span>')
                .replace(/(\[安全预警\].*?:)/g, '<span class="text-red font-bold pulse-text">🚨 $1</span>')
                .replace(/(\[带宽枢纽\].*?:)/g, '<span class="text-blue font-bold">📊 $1</span>');

            html += `<div class="console-line">${colorized}</div>`;
        }
    }

    if (inTable) html += '</tbody></table></div>';

    return html;
}

function getRatioClass(ratio) {
    if (ratio > 0.8) return 'high';
    if (ratio > 0.4) return 'med';
    return 'low';
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
