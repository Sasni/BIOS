/**
 * BIOS Analysis Toolkit — Frontend Application v2
 * Single-file JS, no dependencies (vanilla).
 */

/**
 * Encode a relpath (which may contain \ and spaces) for use in a Flask path parameter.
 */
function encodeRelpath(relpath) {
    // Normalize Windows \ to / for URL, then encode each segment
    return relpath.replace(/\\/g, '/').split('/').map(encodeURIComponent).join('/');
}

// ── State ────────────────────────────────────────────────────────────────────

const state = {
    files: [],
    selectedFile: null,       // relpath string
    currentTab: 'info',
    hexOffset: 0,
    hexTotalSize: 0,
    diffPairs: [],
};

// ── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    refreshFiles();
});

// ── File list ────────────────────────────────────────────────────────────────

async function refreshFiles() {
    const list = document.getElementById('fileList');
    list.innerHTML = '<div class="loading">Loading files...</div>';
    try {
        const resp = await fetch('/api/files');
        state.files = await resp.json();
        renderFileList();
    } catch (e) {
        list.innerHTML = `<div class="error-state">Failed to load files: ${e.message}</div>`;
    }
}

function renderFileList() {
    const list = document.getElementById('fileList');
    if (state.files.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No .bin files found</p></div>';
        return;
    }
    list.innerHTML = state.files.map(f => `
        <div class="file-item ${state.selectedFile === f.relpath ? 'active' : ''}"
             onclick="selectFile('${escapeJs(f.relpath)}')"
             title="${escapeHtml(f.relpath)} (${f.size_mb} MB)"
             onmouseenter="this.querySelector('.delete-btn').style.display='inline'"
             onmouseleave="this.querySelector('.delete-btn').style.display='none'">
            <div class="name">${escapeHtml(f.name)}
                <span class="delete-btn" style="display:none;float:right;cursor:pointer;color:var(--accent-red);font-size:13px;"
                      onclick="event.stopPropagation();deleteFile('${escapeJs(f.relpath)}')"
                      title="Delete this dump">✕</span>
            </div>
            <div class="meta">
                <span>${f.size_mb} MB</span>
                <span class="badge">${formatDate(f.modified)}</span>
            </div>
        </div>
    `).join('');
    // Also populate diff selects
    populateDiffSelects();
}

function selectFile(relpath) {
    state.selectedFile = relpath;
    renderFileList();
    document.getElementById('statusBar').textContent = relpath.split('\\').pop().split('/').pop();
    loadFileInfo(relpath);
    switchTab('info');
}

// ── Tab switching ────────────────────────────────────────────────────────────

function switchTab(tab) {
    state.currentTab = tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
    document.querySelectorAll('.content-area > div[id^="view-"]').forEach(v => v.classList.add('hidden'));
    const target = document.getElementById(`view-${tab}`);
    if (target) target.classList.remove('hidden');

    if (!state.selectedFile && tab !== 'diff' && tab !== 'patches') {
        if (tab !== 'info') {
            setStatus('Select a file first', true);
            document.getElementById('view-info').classList.remove('hidden');
            document.getElementById(`view-${tab}`).classList.add('hidden');
        }
        return;
    }

    switch (tab) {
        case 'info': loadFileInfo(state.selectedFile); break;
        case 'hex': loadHex(); break;
        case 'analyze': loadAnalysis(state.selectedFile); break;
        case 'diff': break; // loaded on demand
        case 'identify': loadIdentify(state.selectedFile); break;
        case 'patches': loadPatches(); break;
    }
}

// ── File Info ────────────────────────────────────────────────────────────────

async function loadFileInfo(relpath) {
    const area = document.getElementById('view-info');
    area.innerHTML = '<div class="loading">Loading file info...</div>';
    try {
        const resp = await fetch(`/api/file-info/${encodeRelpath(relpath)}`);
        const info = await resp.json();
        if (info.error) { area.innerHTML = `<div class="error-state">${info.error}</div>`; return; }
        renderFileInfo(area, info);
    } catch (e) {
        area.innerHTML = `<div class="error-state">${e.message}</div>`;
    }
}

function renderFileInfo(container, info) {
    container.innerHTML = `
        <div class="stats-grid">
            <div class="stat-card"><div class="value">${info.size_mb}</div><div class="label">Size (MB)</div></div>
            <div class="stat-card"><div class="value">${info.size.toLocaleString()}</div><div class="label">Bytes</div></div>
            <div class="stat-card"><div class="value" style="font-size:14px;font-weight:400;">${info.sha256.slice(0,16)}…</div><div class="label">SHA256</div></div>
        </div>
        <div class="panel">
            <div class="panel-header">File Metadata</div>
            <div class="panel-body">
                <div class="info-grid">
                    <span class="key">Name</span><span class="value">${escapeHtml(info.name)}</span>
                    <span class="key">Path</span><span class="value text-sm">${escapeHtml(info.path)}</span>
                    <span class="key">Size</span><span class="value">${info.size.toLocaleString()} bytes (${info.size_mb} MB)</span>
                    <span class="key">SHA256</span><span class="value text-sm">${info.sha256}</span>
                    <span class="key">MD5</span><span class="value text-sm">${info.md5}</span>
                    <span class="key">Modified</span><span class="value">${formatDate(info.modified)}</span>
                </div>
            </div>
        </div>
        <div class="flex gap-2">
            <button class="btn primary" onclick="switchTab('analyze')">Analyze ▶</button>
            <button class="btn" onclick="switchTab('hex')">Hex View ▶</button>
            <button class="btn" onclick="switchTab('identify')">Identify ▶</button>
        </div>
    `;
}

// ── Hex Viewer ───────────────────────────────────────────────────────────────

async function loadHex() {
    if (!state.selectedFile) return;
    const offsetInput = document.getElementById('hexOffset');
    const lengthInput = document.getElementById('hexLength');
    const offset = parseInt(offsetInput.value, 16) || 0;
    const length = parseInt(lengthInput.value, 10) || 256;
    state.hexOffset = offset;
    const area = document.getElementById('hexContent');
    area.innerHTML = '<div class="loading">Loading hex data...</div>';
    try {
        const resp = await fetch(`/api/hex/${encodeRelpath(state.selectedFile)}?offset=${offset}&length=${length}`);
        const data = await resp.json();
        state.hexTotalSize = data.total_size;
        document.getElementById('hexRange').textContent =
            `0x${offset.toString(16)} - 0x${(offset + length).toString(16)} / 0x${data.total_size.toString(16)}`;
        renderHex(area, data);
        updateHexNav();
    } catch (e) {
        area.innerHTML = `<div class="error-state">${e.message}</div>`;
    }
}

function renderHex(container, data) {
    container.innerHTML = data.lines.map(line => `
        <div class="hex-line">
            <span class="hex-addr">0x${line.addr.toString(16).padStart(8, '0')}</span>
            <span class="hex-bytes">
                <span class="group">${line.hex.slice(0, 23)}</span>
                <span class="group">${line.hex.slice(23)}</span>
            </span>
            <span class="hex-ascii">${escapeHtml(line.ascii)}</span>
        </div>
    `).join('');
}

function hexPage(dir) {
    const length = parseInt(document.getElementById('hexLength').value, 10) || 256;
    let newOffset = state.hexOffset + dir * length;
    if (newOffset < 0) newOffset = 0;
    document.getElementById('hexOffset').value = '0x' + newOffset.toString(16);
    loadHex();
}

function updateHexNav() {
    const length = parseInt(document.getElementById('hexLength').value, 10) || 256;
    const total = state.hexTotalSize;
    const current = state.hexOffset;
    document.getElementById('hexPageInfo').textContent =
        `Page ${Math.floor(current / length) + 1} / ${Math.max(1, Math.ceil(total / length))} (${total.toLocaleString()} bytes)`;
}

async function searchHex() {
    if (!state.selectedFile) return;
    const query = document.getElementById('hexSearch').value;
    const mode = document.getElementById('hexSearchMode').value;
    if (!query) return;
    const results = document.getElementById('hexSearchResults');
    results.classList.remove('hidden');
    results.innerHTML = '<div class="loading">Searching...</div>';
    try {
        const resp = await fetch(`/api/hex-search/${encodeRelpath(state.selectedFile)}?q=${encodeURIComponent(query)}&mode=${mode}`);
        const data = await resp.json();
        if (data.error) { results.innerHTML = `<div class="error-state">${data.error}</div>`; return; }
        if (data.matches === 0) {
            results.innerHTML = `<div class="card"><div class="card-title">Search results</div>No matches for "${escapeHtml(query)}"</div>`;
            return;
        }
        let posHtml = data.positions.slice(0, 50).map(p =>
            `<span class="hex-byte" style="cursor:pointer;color:var(--accent);text-decoration:underline;" onclick="jumpToHex(0x${p.toString(16)})">0x${p.toString(16).padStart(8,'0')}</span>`
        ).join(', ');
        if (data.positions.length > 50) posHtml += `, … and ${data.positions.length - 50} more`;
        results.innerHTML = `
            <div class="card">
                <div class="card-title">Search: "${escapeHtml(data.query)}" — ${data.matches} match${data.matches !== 1 ? 'es' : ''} (${data.pattern_len} bytes)</div>
                <div class="text-sm">${posHtml}</div>
            </div>
        `;
    } catch (e) {
        results.innerHTML = `<div class="error-state">${e.message}</div>`;
    }
}

function jumpToHex(offset) {
    const length = parseInt(document.getElementById('hexLength').value, 10) || 256;
    // center the offset in the view
    const viewStart = Math.max(0, offset - Math.floor(length / 2));
    document.getElementById('hexOffset').value = '0x' + viewStart.toString(16);
    loadHex();
}

// ── Analysis ─────────────────────────────────────────────────────────────────

async function loadAnalysis(relpath) {
    const area = document.getElementById('view-analyze');
    area.innerHTML = '<div class="loading">Running analysis...</div>';
    try {
        const resp = await fetch(`/api/analyze/${encodeRelpath(relpath)}`);
        const data = await resp.json();
        if (data.error) { area.innerHTML = `<div class="error-state">${data.error}</div>`; return; }
        renderAnalysis(area, data);
    } catch (e) {
        area.innerHTML = `<div class="error-state">${e.message}</div>`;
    }
}

function renderAnalysis(container, data) {
    const parse = data.parse;
    const fit = data.fit;
    let html = `<div class="stats-grid">
        <div class="stat-card"><div class="value">${data.sha256.slice(0, 16)}…</div><div class="label">SHA256</div></div>
    </div>`;

    // Parse tool output
    if (parse.data) {
        const p = parse.data;
        html += `<div class="panel"><div class="panel-header">Parse Results</div><div class="panel-body">`;
        html += `<pre class="output">${escapeHtml(JSON.stringify(p, null, 2))}</pre>`;
        html += `</div></div>`;
    } else if (parse.stdout) {
        html += `<div class="panel"><div class="panel-header">Parse Output</div><div class="panel-body">`;
        html += `<pre class="output">${escapeHtml(parse.stdout)}</pre>`;
        html += `</div></div>`;
    }

    // FIT parser output
    if (fit && fit.data) {
        html += `<div class="panel"><div class="panel-header">Intel FIT</div><div class="panel-body">`;
        html += `<pre class="output">${escapeHtml(JSON.stringify(fit.data, null, 2))}</pre>`;
        html += `</div></div>`;
    } else if (fit && fit.stdout) {
        html += `<div class="panel"><div class="panel-header">Intel FIT</div><div class="panel-body">`;
        html += `<pre class="output">${escapeHtml(fit.stdout)}</pre>`;
        html += `</div></div>`;
    }

    if (parse.error) {
        html += `<div class="error-state">Parse error: ${parse.error}</div>`;
    }

    if (!parse.data && !parse.stdout && !parse.error) {
        html += `<div class="empty-state"><p>No analysis data returned.</p></div>`;
        if (parse.stderr) {
            html += `<pre class="output mt-2">${escapeHtml(parse.stderr)}</pre>`;
        }
    }

    container.innerHTML = html;
}

// ── Diff ─────────────────────────────────────────────────────────────────────

function populateDiffSelects() {
    const orig = document.getElementById('diffOrig');
    const rep = document.getElementById('diffRep');
    orig.innerHTML = state.files.map(f =>
        `<option value="${escapeHtml(f.relpath)}">${escapeHtml(f.name)} (${f.size_mb}MB)</option>`
    ).join('');
    rep.innerHTML = state.files.map(f =>
        `<option value="${escapeHtml(f.relpath)}">${escapeHtml(f.name)} (${f.size_mb}MB)</option>`
    ).join('');
}

async function loadDiff() {
    const orig = document.getElementById('diffOrig').value;
    const rep = document.getElementById('diffRep').value;
    if (!orig || !rep) return;
    const area = document.getElementById('diffContent');
    area.innerHTML = '<div class="loading">Comparing...</div>';
    try {
        const resp = await fetch(`/api/diff/${encodeRelpath(orig)}/${encodeRelpath(rep)}`);
        const data = await resp.json();
        if (data.error) { area.innerHTML = `<div class="error-state">${data.error}</div>`; return; }
        renderDiff(area, data);
    } catch (e) {
        area.innerHTML = `<div class="error-state">${e.message}</div>`;
    }
}

function renderDiff(container, data) {
    const diff = data.diff;
    if (!diff) {
        container.innerHTML = '<div class="empty-state"><p>No diff data returned.</p></div>';
        return;
    }

    let html = `<div class="panel">
        <div class="panel-header">Diff: ${escapeHtml(data.original)} ↔ ${escapeHtml(data.repaired)}</div>
        <div class="panel-body">`;

    if (diff.data && diff.data.changes) {
        const changes = diff.data.changes;
        html += `<div class="stats-grid" style="grid-template-columns:repeat(3,1fr);">
            <div class="stat-card"><div class="value">${changes.length || 0}</div><div class="label">Changed Regions</div></div>
        </div>`;
        html += `<div class="diff-viewer">`;
        // Show changed bytes
        if (Array.isArray(changes)) {
            changes.slice(0, 100).forEach(c => {
                const cls = c.type === 'added' ? 'added' : c.type === 'removed' ? 'removed' : 'modified';
                html += `<div class="diff-line ${cls}">
                    <span class="diff-addr">0x${(c.offset || 0).toString(16).padStart(8, '0')}</span>
                    <span class="diff-bytes">${escapeHtml(c.description || JSON.stringify(c))}</span>
                </div>`;
            });
            if (changes.length > 100) {
                html += `<div class="diff-line text-muted">… and ${changes.length - 100} more changes</div>`;
            }
        }
        html += `</div>`;
    } else if (diff.stdout) {
        html += `<pre class="output">${escapeHtml(diff.stdout)}</pre>`;
    } else {
        html += `<div class="empty-state"><p>No differences detected or format unrecognized.</p></div>`;
    }

    if (diff.stderr) {
        html += `<pre class="output mt-2">${escapeHtml(diff.stderr)}</pre>`;
    }

    if (diff.error) {
        html += `<div class="error-state">${diff.error}</div>`;
    }

    html += `</div></div>`;
    container.innerHTML = html;
}

// ── Identify ─────────────────────────────────────────────────────────────────

async function loadIdentify(relpath) {
    const area = document.getElementById('view-identify');
    area.innerHTML = '<div class="loading">Identifying against model database...</div>';
    try {
        const resp = await fetch(`/api/identify/${encodeRelpath(relpath)}`);
        const data = await resp.json();
        if (data.error) { area.innerHTML = `<div class="error-state">${data.error}</div>`; return; }
        renderIdentify(area, data);
    } catch (e) {
        area.innerHTML = `<div class="error-state">${e.message}</div>`;
    }
}

function renderIdentify(container, data) {
    const r = data.result;
    let html = `<div class="panel">
        <div class="panel-header">Identification: ${escapeHtml(data.file)}</div>
        <div class="panel-body">`;

    if (r.data) {
        html += `<pre class="output">${escapeHtml(JSON.stringify(r.data, null, 2))}</pre>`;
    } else if (r.stdout) {
        html += `<pre class="output">${escapeHtml(r.stdout)}</pre>`;
    } else {
        html += `<div class="empty-state"><p>No identification data returned.</p></div>`;
    }

    if (r.error) {
        html += `<div class="error-state">${r.error}</div>`;
    }

    html += `</div></div>`;
    container.innerHTML = html;
}

// ── Patches ──────────────────────────────────────────────────────────────────

async function loadPatches() {
    const area = document.getElementById('view-patches');
    try {
        const resp = await fetch('/api/patches');
        const patches = await resp.json();
        renderPatches(area, patches);
    } catch (e) {
        area.innerHTML = `<div class="error-state">${e.message}</div>`;
    }
}

function renderPatches(container, patches) {
    if (!patches || patches.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No patches available. Add .py scripts to tools/patches/</p></div>';
        return;
    }
    let html = `<div class="panel">
        <div class="panel-header">Available Patches</div>
        <div class="panel-body">`;
    html += patches.map(p => `
        <div class="card flex" style="justify-content:space-between;align-items:center;">
            <div>
                <strong>${escapeHtml(p.name)}</strong>
                <div class="text-sm text-muted">${formatDate(p.modified)}</div>
            </div>
            <div>
                <button class="btn small primary" onclick="applyPatch('${escapeJs(p.name)}')">Apply</button>
            </div>
        </div>
    `).join('');
    html += `</div></div>`;
    container.innerHTML = html;
}

async function applyPatch(patchName) {
    if (!state.selectedFile) {
        setStatus('Select a file first', true);
        return;
    }
    if (!confirm(`Apply patch "${patchName}" to "${state.selectedFile}"?`)) return;
    const area = document.getElementById('view-patches');
    area.innerHTML += `<div class="loading">Applying patch "${patchName}"...</div>`;
    try {
        const resp = await fetch('/api/patch/apply', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({patch: patchName, input: state.selectedFile})
        });
        const result = await resp.json();
        if (result.error) {
            area.innerHTML += `<div class="error-state">${result.error}</div>`;
        } else {
            area.innerHTML += `<div class="panel"><div class="panel-header">Patch Result</div><div class="panel-body">
                <pre class="output">${escapeHtml(JSON.stringify(result, null, 2))}</pre>
            </div></div>`;
            // Refresh file list to show new patched file
            refreshFiles();
        }
    } catch (e) {
        area.innerHTML += `<div class="error-state">${e.message}</div>`;
    }
}

// ── DB Stats ─────────────────────────────────────────────────────────────────

async function showDbStats() {
    try {
        const resp = await fetch('/api/db/stats');
        const stats = await resp.json();
        if (stats.exists && stats.models > 0) {
            setStatus(`DB: ${stats.models} model(s) — ${stats.path}`);
        } else if (stats.exists) {
            setStatus('DB file exists but empty');
        } else {
            setStatus('No model database yet — run batch process');
        }
    } catch (e) {
        setStatus(`DB error: ${e.message}`, true);
    }
}

// ── Upload & Delete ──────────────────────────────────────────────────────────

async function uploadFile(input) {
    const file = input.files[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.bin')) {
        setStatus('Only .bin files allowed', true);
        input.value = '';
        return;
    }
    const formData = new FormData();
    formData.append('file', file);
    setStatus(`Uploading ${file.name}...`);
    try {
        const resp = await fetch('/api/upload', { method: 'POST', body: formData });
        const result = await resp.json();
        if (result.error) {
            setStatus(`Upload failed: ${result.error}`, true);
        } else {
            setStatus(`Uploaded: ${result.relpath} (${(result.size / 1048576).toFixed(1)} MB)`);
            refreshFiles();
        }
    } catch (e) {
        setStatus(`Upload error: ${e.message}`, true);
    }
    input.value = '';
}

async function deleteFile(relpath) {
    const name = relpath.split('\\').pop().split('/').pop();
    if (!confirm(`Delete "${name}" permanently?\n\nThis also removes its analysis JSON.`)) return;
    try {
        const resp = await fetch(`/api/delete/${encodeRelpath(relpath)}`, { method: 'DELETE' });
        const result = await resp.json();
        if (result.error) {
            setStatus(`Delete failed: ${result.error}`, true);
        } else {
            if (state.selectedFile === relpath) {
                state.selectedFile = null;
                document.getElementById('statusBar').textContent = 'No file selected';
            }
            refreshFiles();
            setStatus(`Deleted: ${name}`);
        }
    } catch (e) {
        setStatus(`Delete error: ${e.message}`, true);
    }
}

// ── Status ───────────────────────────────────────────────────────────────────

function setStatus(msg, isError) {
    const el = document.getElementById('statusBar');
    el.textContent = msg;
    el.style.color = isError ? 'var(--accent-red)' : '';
    if (!isError) {
        setTimeout(() => { el.style.color = ''; }, 3000);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (typeof str !== 'string') str = String(str);
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function escapeJs(str) {
    return str.replace(/'/g, "\\'").replace(/"/g, '\\"');
}

function formatDate(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return d.toLocaleDateString('pl-PL', {month:'short', day:'numeric', year:'numeric', hour:'2-digit', minute:'2-digit'});
}
