/**
 * BIOS Analysis Toolkit — Frontend Application
 * Single-file JS, no dependencies (vanilla).
 */

/**
 * Encode a relpath (which may contain \ and spaces) for use in a Flask path parameter.
 */
function encodeRelpath(relpath) {
    // Normalize Windows backslashes to forward slashes for URL paths,
    // then encode everything except the / separators Flask needs for <path:> routing.
    return encodeURIComponent(relpath.replace(/\\/g, '/')).replace(/%2F/gi, '/');
}

// ── State ────────────────────────────────────────────────────────────────────

const state = {
    selectedFile: null,       // { name, relpath, path, size, size_mb, sha256 }
    diffFile: null,           // second file for comparison
    currentTab: 'info',
    hexOffset: 0,
    hexTotalSize: 0,
    hexLoadedEnd: 0,
    analysisData: null,       // cached parse_bios output for the selected file
};

// ── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    showDbStats();
});

// ── Upload / Drag & Drop ─────────────────────────────────────────────────────

function onDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.classList.add('drag-over');
}

function onDragLeave(e) {
    e.currentTarget.classList.remove('drag-over');
}

async function onDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) await handleUpload(file);
}

async function onFileSelected(input) {
    const file = input.files[0];
    if (file) await handleUpload(file);
    input.value = '';
}

async function handleUpload(file) {
    if (!file.name.toLowerCase().endsWith('.bin')) {
        setStatus('Only .bin files allowed', true);
        return;
    }
    setStatus(`Uploading ${file.name}...`);
    const formData = new FormData();
    formData.append('file', file);
    try {
        const resp = await fetch('/api/upload', { method: 'POST', body: formData });
        const result = await resp.json();
        if (result.error) {
            setStatus(`Upload failed: ${result.error}`, true);
            return;
        }
        // Get file info
        const infoResp = await fetch(`/api/file-info/${encodeRelpath(result.relpath)}`);
        const info = await infoResp.json();
        if (info.error) {
            setStatus(`Upload OK but info failed: ${info.error}`, true);
            return;
        }
        state.selectedFile = info;
        state.diffFile = null;
        showFileInSidebar(info);
        setStatus(`Loaded: ${info.name} (${info.size_mb} MB)`);
        loadFileInfo(info);
        // Auto-start analysis in background
        loadAnalysis(info.relpath || info.path);
        switchTab('info');
        // Reset hex state
        state.hexOffset = 0;
        state.hexTotalSize = 0;
        state.hexLoadedEnd = 0;
    } catch (e) {
        setStatus(`Upload error: ${e.message}`, true);
    }
}

function showFileInSidebar(info) {
    document.getElementById('uploadZone').classList.add('hidden');
    const panel = document.getElementById('fileInfoPanel');
    panel.classList.remove('hidden');
    document.getElementById('sidebarFileName').textContent = info.name;
    document.getElementById('sidebarFileMeta').innerHTML =
        `${info.size_mb} MB &middot; SHA256 ${info.sha256.slice(0, 16)}&hellip;`;
    document.getElementById('diffOrigLabel').textContent = info.name;
}

function clearFile() {
    state.selectedFile = null;
    state.diffFile = null;
    document.getElementById('uploadZone').classList.remove('hidden');
    document.getElementById('fileInfoPanel').classList.add('hidden');
    document.getElementById('diffOrigLabel').textContent = '(uploaded file)';
    document.getElementById('statusBar').textContent = 'Drop a .bin file to start';
    // Clear content areas
    document.getElementById('view-info').innerHTML =
        `<div class="empty-state"><div class="icon">📂</div><p>Drop a BIOS dump on the left panel to begin.</p></div>`;
    switchTab('info');
}

// ── Diff second file upload ──────────────────────────────────────────────────

async function onDiffDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    e.currentTarget.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) await handleDiffUpload(file);
}

async function onDiffFileSelected(input) {
    const file = input.files[0];
    if (file) await handleDiffUpload(file);
    input.value = '';
}

async function handleDiffUpload(file) {
    if (!file.name.toLowerCase().endsWith('.bin')) {
        setStatus('Only .bin files allowed', true);
        return;
    }
    setStatus(`Uploading diff file: ${file.name}...`);
    const formData = new FormData();
    formData.append('file', file);
    try {
        const resp = await fetch('/api/upload', { method: 'POST', body: formData });
        const result = await resp.json();
        if (result.error) { setStatus(result.error, true); return; }
        const infoResp = await fetch(`/api/file-info/${encodeRelpath(result.relpath)}`);
        const info = await infoResp.json();
        if (info.error) { setStatus(info.error, true); return; }
        state.diffFile = info;
        document.getElementById('diffUploadZone').textContent = info.name + ` (${info.size_mb} MB)`;
        setStatus(`Diff file: ${info.name}`);
    } catch (e) {
        setStatus(`Upload error: ${e.message}`, true);
    }
}

// ── Tab switching ────────────────────────────────────────────────────────────

function switchTab(tab) {
    state.currentTab = tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
    document.querySelectorAll('.content-area > div[id^="view-"]').forEach(v => v.classList.add('hidden'));
    const target = document.getElementById(`view-${tab}`);
    if (target) target.classList.remove('hidden');

    if (!state.selectedFile && tab !== 'fix') {
        if (tab !== 'info') {
            setStatus('Upload a file first', true);
            document.getElementById('view-info').classList.remove('hidden');
            if (target) target.classList.add('hidden');
        }
        return;
    }

    const relpath = state.selectedFile ? state.selectedFile.relpath || state.selectedFile.path : null;

    switch (tab) {
        case 'info':
            if (state.selectedFile) loadFileInfo(state.selectedFile);
            break;
        case 'hex': loadHex(); break;
        case 'diff': break;
        case 'vars': loadVars(); break;
        case 'fix': loadFix(); break;
    }
}

// ── File Info ────────────────────────────────────────────────────────────────

async function loadFileInfo(infoObj) {
    const area = document.getElementById('view-info');
    // If we already have the info (from upload), use it; otherwise fetch
    if (infoObj && infoObj.sha256) {
        renderFileInfo(area, infoObj);
        // Re-render cached analysis if available (e.g., returning from another tab)
        reRenderAnalysis();
        return;
    }
    const relpath = typeof infoObj === 'string' ? infoObj : (infoObj && infoObj.relpath);
    if (!relpath) return;
    area.innerHTML = '<div class="loading">Loading file info...</div>';
    try {
        const resp = await fetch(`/api/file-info/${encodeRelpath(relpath)}`);
        const info = await resp.json();
        if (info.error) { area.innerHTML = `<div class="error-state">${info.error}</div>`; return; }
        renderFileInfo(area, info);
        reRenderAnalysis();
    } catch (e) {
        area.innerHTML = `<div class="error-state">${e.message}</div>`;
    }
}

function reRenderAnalysis() {
    // Re-render the analysis section from cached data (survives tab switches).
    if (state.analysisData) {
        renderAnalysisIntoInfo(state.analysisData);
    }
}

function renderFileInfo(container, info) {
    container.innerHTML = `
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
            <button class="btn" onclick="switchTab('hex')">Hex View ▶</button>
        </div>
    `;
}

// ── Hex Viewer ───────────────────────────────────────────────────────────────

const HEX_CHUNK = 4096;  // bytes per chunk loaded on scroll

async function loadHex(fromOffset = null) {
    const relpath = state.selectedFile ? (state.selectedFile.relpath || state.selectedFile.path) : null;
    if (!relpath) return;
    const reset = fromOffset !== null || state.hexLoadedEnd === undefined;
    const offset = fromOffset !== null ? fromOffset : (state.hexLoadedEnd || 0);
    if (!reset && state.hexTotalSize && offset >= state.hexTotalSize) return; // EOF
    const area = document.getElementById('hexContent');
    if (reset) {
        area.innerHTML = '<div class="loading">Loading hex data...</div>';
    }
    const el = document.getElementById('hexLoadStatus');
    if (el) el.textContent = 'Loading...';
    try {
        const resp = await fetch(`/api/hex/${encodeRelpath(relpath)}?offset=${offset}&length=${HEX_CHUNK}`);
        const data = await resp.json();
        if (data.error) { area.innerHTML = `<div class="error-state">${data.error}</div>`; return; }
        state.hexTotalSize = data.total_size;
        state.hexOffset = offset;
        state.hexLoadedEnd = offset + data.length;
        document.getElementById('hexRange').textContent =
            `0x0 - 0x${state.hexLoadedEnd.toString(16)} / 0x${data.total_size.toString(16)}`;
        if (reset) {
            renderHex(area, data, true);
        } else {
            appendHex(area, data);
        }
        const remaining = data.total_size - state.hexLoadedEnd;
        if (el) el.textContent = remaining > 0
            ? `Loaded 0x0–0x${state.hexLoadedEnd.toString(16)}  |  ${(remaining / 1024).toFixed(0)} KB remaining — scroll for more`
            : `All ${(data.total_size / 1024).toFixed(0)} KB loaded`;
    } catch (e) {
        area.innerHTML = `<div class="error-state">${e.message}</div>`;
    }
}

function renderHex(container, data, clear = false) {
    const html = data.lines.map(line => `
        <div class="hex-line" id="hex-${line.addr.toString(16).padStart(8, '0')}">
            <span class="hex-addr">0x${line.addr.toString(16).padStart(8, '0')}</span>
            <span class="hex-bytes">
                <span class="group">${line.hex.slice(0, 23)}</span>
                <span class="group">${line.hex.slice(23)}</span>
            </span>
            <span class="hex-ascii">${escapeHtml(line.ascii)}</span>
        </div>
    `).join('');
    container.innerHTML = html;
}

function appendHex(container, data) {
    const html = data.lines.map(line => `
        <div class="hex-line" id="hex-${line.addr.toString(16).padStart(8, '0')}">
            <span class="hex-addr">0x${line.addr.toString(16).padStart(8, '0')}</span>
            <span class="hex-bytes">
                <span class="group">${line.hex.slice(0, 23)}</span>
                <span class="group">${line.hex.slice(23)}</span>
            </span>
            <span class="hex-ascii">${escapeHtml(line.ascii)}</span>
        </div>
    `).join('');
    container.insertAdjacentHTML('beforeend', html);
}

function onHexScroll() {
    const area = document.getElementById('hexContent');
    if (!area || !state.hexTotalSize) return;
    // Load more when within 500px of the bottom
    const nearBottom = area.scrollHeight - area.scrollTop - area.clientHeight < 500;
    if (nearBottom && state.hexLoadedEnd < state.hexTotalSize) {
        loadHex();  // no offset → continues from hexLoadedEnd
    }
}

function jumpToHex(offset) {
    document.getElementById('hexOffset').value = '0x' + offset.toString(16);
    loadHex(offset);
    // Scroll to top of hex viewer after load
    setTimeout(() => {
        const area = document.getElementById('hexContent');
        if (area) area.scrollTop = 0;
    }, 200);
}

async function searchHex() {
    const relpath = state.selectedFile ? (state.selectedFile.relpath || state.selectedFile.path) : null;
    if (!relpath) return;
    const query = document.getElementById('hexSearch').value;
    const mode = document.getElementById('hexSearchMode').value;
    if (!query) return;
    const results = document.getElementById('hexSearchResults');
    results.classList.remove('hidden');
    results.innerHTML = '<div class="loading">Searching...</div>';
    try {
        const resp = await fetch(`/api/hex-search/${encodeRelpath(relpath)}?q=${encodeURIComponent(query)}&mode=${mode}`);
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

// ── Analysis (renders into Info view) ────────────────────────────────────────

async function loadAnalysis(relpath) {
    if (!relpath) return;
    // Show loading indicator in the info view
    const infoArea = document.getElementById('view-info');
    let loadEl = document.getElementById('analysisLoading');
    if (!loadEl) {
        loadEl = document.createElement('div');
        loadEl.id = 'analysisLoading';
        loadEl.className = 'loading';
        loadEl.textContent = 'Running analysis...';
        infoArea.appendChild(loadEl);
    }
    try {
        const resp = await fetch(`/api/analyze/${encodeRelpath(relpath)}`);
        const data = await resp.json();
        loadEl.remove();
        if (data.error) {
            infoArea.insertAdjacentHTML('beforeend', `<div class="error-state">Analysis: ${escapeHtml(data.error)}</div>`);
            return;
        }
        state.analysisData = data;
        renderAnalysisIntoInfo(data);
    } catch (e) {
        loadEl.remove();
        infoArea.insertAdjacentHTML('beforeend', `<div class="error-state">Analysis: ${e.message}</div>`);
    }
}

// Called internally — appends analysis results below file metadata in the Info view
function meRow(label, value) {
    return `<span class="key">${label}</span><span class="value">${value}</span>`;
}

function renderAnalysisIntoInfo(data) {
    const p = (data.parse && data.parse.data) ? data.parse.data : null;
    const fit = data.fit;
    const fd = data.fd_audit;
    const sb = data.secureboot;
    let html = '';

    // Remove any previous analysis section
    const prev = document.getElementById('analysisSection');
    if (prev) prev.remove();

    html += `<div id="analysisSection" style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border);">`;

    // ── Vendor / Model / Board (NAJWAŻNIEJSZE dla serwisanta) ────────────
    if (p) {
        const idParts = [];
        if (p.detected_vendor) idParts.push(`<b>${escapeHtml(p.detected_vendor)}</b>`);
        if (p.detected_model) idParts.push(escapeHtml(p.detected_model));
        if (p.bios_version && p.bios_version !== 'Unknown') idParts.push(`v${escapeHtml(p.bios_version)}`);
        if (p.board_id) idParts.push(`Board: ${escapeHtml(p.board_id)}`);

        if (idParts.length > 0) {
            html += `<div style="margin-bottom:10px;padding:8px 10px;background:var(--accent-bg);border-radius:6px;border-left:3px solid var(--accent);">`;
            html += `<div style="font-size:14px;font-weight:700;">${idParts.join(' — ')}</div>`;
            const metaParts = [];
            if (p.bios_date) metaParts.push(`Build date: ${escapeHtml(p.bios_date)}`);
            if (p.dump_type) {
                const dtLabel = p.dump_type === 'full_spi' ? 'Full SPI dump' :
                                p.dump_type === 'bios_region' ? 'BIOS region only' :
                                p.dump_type === 'me_region' ? 'ME region' :
                                p.dump_type === 'gbe_region' ? 'GbE region' :
                                p.dump_type;
                metaParts.push(dtLabel);
            }
            if (p.compression && p.compression !== 'none') metaParts.push(`Compression: ${p.compression}`);
            // Serial / UUID / Windows key (redacted by default)
            if (p.serial_number && p.serial_number.length > 2 && p.serial_number !== 'REDACTED') metaParts.push('S/N: ' + escapeHtml(p.serial_number));
            if (p.windows_key && p.windows_key.length > 5 && p.windows_key !== 'REDACTED') metaParts.push('Key: ' + escapeHtml(p.windows_key));
            if (metaParts.length > 0) {
                html += `<div style="font-size:11px;color:var(--muted);margin-top:2px;">${metaParts.join(' · ')}</div>`;
            }
            html += `</div>`;
        }
    }

    // ── Stats row ─────────────────────────────────────────────────────────
    if (p) {
        html += `<div class="stats-grid" style="grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:6px;margin-bottom:8px;">`;
        html += statCard(p.dump_type || '?', 'Type');
        html += statCard(p.compression || 'none', 'Compr');
        if (p.regions) html += statCard(p.regions.length, 'Regions');
        if (p.uefi_volumes) html += statCard(p.uefi_volumes.length, 'FV vols');
        if (p.ami_modules) html += statCard(p.ami_modules.total_modules, 'AMI');
        if (p.ami_format) html += statCard(p.ami_format, 'Format');
        html += `</div>`;
    }

    // ── Regions ───────────────────────────────────────────────────────────
    if (p && p.regions && p.regions.length) {
        html += `<details open class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">Regions (${p.regions.length})</summary>`;
        for (const r of p.regions) {
            const off = typeof r.offset === 'number' ? '0x' + r.offset.toString(16).toUpperCase() : r.offset;
            const sz = r.size >= 1048576 ? (r.size / 1048576).toFixed(1) + ' MB' : r.size >= 1024 ? (r.size / 1024).toFixed(0) + ' KB' : r.size + ' B';
            const ent = r.entropy !== undefined ? `entropy ${r.entropy.toFixed(1)}` : '';
            html += `<div class="flex" style="justify-content:space-between;padding:2px 8px;font-size:13px;">
                <span>${escapeHtml(r.name)}</span>
                <span class="text-muted">${off} &ndash; ${sz} ${ent}</span></div>`;
        }
        html += `</details>`;
    }

    // ── UEFI Volumes ──────────────────────────────────────────────────────
    if (p && p.uefi_volumes && p.uefi_volumes.length) {
        html += `<details class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">UEFI Firmware Volumes (${p.uefi_volumes.length})</summary>`;
        for (const fv of p.uefi_volumes) {
            const off = '0x' + (fv.offset || 0).toString(16).toUpperCase();
            html += `<div class="flex" style="justify-content:space-between;padding:2px 8px;font-size:13px;">
                <span>FV at ${off}</span>
                <span class="text-muted">${fv.size}B &middot; ${fv.validated ? 'ok' : '?'}</span></div>`;
        }
        html += `</details>`;
    }

    // ── UEFI Volume Deep Scan (FFS files) ─────────────────────────────────
    if (p && p.uefi_volume_deep_scan && p.uefi_volume_deep_scan.length) {
        for (const fv of p.uefi_volume_deep_scan) {
            const fvOff = '0x' + (fv.volume_offset || 0).toString(16).toUpperCase();
            const guidShort = (fv.volume_guid || 'unknown').substring(0, 16);
            html += `<details class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">FV at ${fvOff} — ${fv.files_found||0} FFS files</summary>`;
            html += `<div style="max-height:300px;overflow-y:auto;font-size:11px;">`;
            if (fv.files && fv.files.length) {
                for (const f of fv.files) {
                    html += `<div class="flex" style="justify-content:space-between;padding:1px 6px;border-top:1px solid var(--border);font-family:monospace;">
                        <span>${escapeHtml(f.type_name || '?')}</span>
                        <span>${escapeHtml(f.name_guid ? f.name_guid.substring(0,16)+'...' : '?')}</span>
                        <span class="text-muted">@0x${(f.offset||0).toString(16).toUpperCase()} ${(f.size||0)}B</span>
                        <span class="text-muted">${f.sections ? f.sections.length + ' sec' : ''} ${f.has_ext_header ? '+ext' : ''}</span>
                    </div>`;
                    // Show sections if any
                    if (f.sections && f.sections.length) {
                        for (const sec of f.sections) {
                            html += `<div class="flex" style="justify-content:space-between;padding:0px 6px 0px 20px;font-size:10px;color:var(--muted);font-family:monospace;">
                                <span>└ ${escapeHtml(sec.type_name || 'section')}</span>
                                <span>${sec.size||0}B ${sec.compression ? '('+sec.compression+')' : ''} ${sec.decompressed_size ? '→'+sec.decompressed_size+'B' : ''}</span>
                            </div>`;
                        }
                    }
                }
            } else {
                html += `<div class="text-muted">No FFS files found (volume may be empty, compressed, or using non-standard format)</div>`;
            }
            html += `</div></details>`;
        }
    }

    // ── Chipset Components (quick summary: GbE + NVRAM + MACs) ────────────
    if (p) {
        const comps = [];

        // GbE region
        if (p.gbe_region && p.gbe_region.detected) {
            const gmacs = (p.gbe_region.mac_candidates || []).filter(m => !m.startsWith('00:00') && !m.startsWith('FF:FF') && !m.endsWith('FF:FF')).slice(0, 2);
            const macStr = gmacs.length > 0 ? `MAC ${gmacs.join(' / ')}` : 'no valid MAC';
            const offs = (p.gbe_region.positions || []).map(o => '0x' + o.toString(16).toUpperCase()).join(', ');
            comps.push(`<span><b>GbE</b>: at ${offs} &middot; <span style="font-family:monospace;">${escapeHtml(macStr)}</span></span>`);
        } else if (p.gbe_region && !p.gbe_region.detected) {
            comps.push(`<span><b>GbE</b>: not detected</span>`);
        }

        // MAC addresses extracted
        if (p.mac_addresses && p.mac_addresses.length) {
            const macs = p.mac_addresses.slice(0, 4).join(' / ');
            comps.push(`<span><b>MACs</b>: <span style="font-family:monospace;">${escapeHtml(macs)}</span>${p.mac_addresses.length > 4 ? ' +'+(p.mac_addresses.length-4)+' more' : ''}</span>`);
        }

        // NVRAM store
        if (p.nvram_store && p.nvram_store.detected) {
            const offs = (p.nvram_store.positions || []).map(o => '0x' + o.toString(16).toUpperCase()).join(', ');
            comps.push(`<span><b>NVRAM store</b>: at ${offs}</span>`);
        }

        if (comps.length > 0) {
            html += `<div style="margin-bottom:8px;padding:6px 8px;font-size:12px;background:var(--panel);border-radius:4px;">`;
            html += comps.join(' &nbsp;|&nbsp; ');
            html += `</div>`;
        }
    }

    // ── Intel ME (pełna sekcja, analogicznie do ME Analyzer) ──────────────
    const meInfo = (p && p.me_info) ? p.me_info : null;
    if (meInfo || (p && p.dump_type)) {
        html += `<details open class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">Intel ME — ${meInfo && meInfo.found ? 'v' + escapeHtml(meInfo.version || '?') : meInfo && !meInfo.found ? 'not found' : 'not available'}</summary>`;
        html += `<div style="font-size:12px;padding:4px 8px;">`;

        if (!meInfo) {
            // ME parser didn't run — explain why
            html += `<div style="color:var(--muted);">ME region not available in this dump.</div>`;
            html += `<div style="font-size:11px;color:var(--muted);">`;
            if (p.dump_type === 'bios_region') {
                html += `This is a <b>BIOS region</b> dump — the ME partition (offset 0x1000–0x300000) is not included.<br>`;
                html += `To see ME info, use a <b>full SPI dump</b> (8–64 MB file containing the complete flash contents including IFD, ME, BIOS, GbE, and PDR regions).`;
            } else if (p.dump_type === 'me_region') {
                html += `This is an <b>ME region</b> dump — run <code>me_parser.py</code> directly on this file for full ME analysis.`;
            } else {
                html += `ME parser did not run — dump type: ${escapeHtml(p.dump_type || 'unknown')}`;
            }
            html += `</div>`;
        } else if (meInfo.found) {
            // Full ME Analyzer-style table
            html += `<div class="info-grid" style="grid-template-columns:180px 1fr;">`;
            const dbLabel = meInfo.from_mea_db ? ' <span style=\"font-size:10px;color:#6c6;\">(MEA database)</span>' :
                            meInfo.from_database ? ' <span style=\"font-size:10px;color:var(--accent);\">(cache lookup)</span>' : '';
            html += meRow('Family', 'ME' + dbLabel);
            html += meRow('Version', escapeHtml(meInfo.version || 'unknown'));
            html += meRow('Release', escapeHtml(meInfo.release_type || 'unknown'));
            html += meRow('Type', escapeHtml(meInfo.me_type || (meInfo.from_database ? 'Stock' : 'Region')));
            html += meRow('FD', meInfo.locked ? '<span style="color:#6c6;">Locked</span>' : '<span style="color:#e55;">Unlocked</span>');
            html += meRow('SKU', escapeHtml(meInfo.sku_size || 'unknown'));
            if (meInfo.svn > 0) html += meRow('Security Version Number', meInfo.svn);
            if (meInfo.vcn > 0) html += meRow('Version Control Number', meInfo.vcn);
            html += meRow('Production Ready', meInfo.production_ready ? '<span style="color:#6c6;">Yes</span>' : '<span style="color:#e55;">No</span>');
            if (meInfo.build_date) html += meRow('Date', escapeHtml(meInfo.build_date));
            // Use actual firmware size if known (from cache/MEA), otherwise region size
            const meActualSize = meInfo.me_size || meInfo.me_region_size || 0;
            const meSizeStr = '0x' + meActualSize.toString(16).toUpperCase() + ' (' + (meActualSize >= 1048576 ? (meActualSize/1048576).toFixed(1)+' MB' : (meActualSize/1024).toFixed(0)+' KB') + ')';
            html += meRow('Size', meSizeStr);
            if (meInfo.platform) html += meRow('Chipset Support', escapeHtml(meInfo.platform));
            if (meInfo.is_latest !== null && meInfo.is_latest !== undefined) {
                html += meRow('Latest', meInfo.is_latest ? '<span style="color:#6c6;">Yes</span>' : '<span style="color:#e8b739;">No</span>');
            }
            if (meInfo.fpt_version > 0) html += meRow('FPT Version', meInfo.fpt_version);
            html += meRow('Partitions', (meInfo.partitions || []).length);
            html += `</div>`;

            // Partitions list
            if (meInfo.partitions && meInfo.partitions.length > 0) {
                html += `<div style="margin-top:6px;"><b>Partitions:</b></div>`;
                html += `<div style="font-family:monospace;font-size:11px;max-height:150px;overflow-y:auto;">`;
                for (const part of meInfo.partitions) {
                    html += `<div class="flex" style="justify-content:space-between;padding:1px 6px;border-top:1px solid var(--border);">`;
                    html += `<span>${escapeHtml(part.name)}</span>`;
                    html += `<span>offset=0x${(part.offset||'').toString()}  size=${escapeHtml(part.length_formatted || (part.length||0)+'B')}</span>`;
                    html += `</div>`;
                }
                html += `</div>`;
            }
        } else {
            // ME not found — explain why
            html += `<div style="color:var(--muted);">${escapeHtml(meInfo.summary || 'ME firmware not detected')}</div>`;
            if (meInfo.notes && meInfo.notes.length) {
                for (const n of meInfo.notes) {
                    html += `<div class="text-muted" style="font-size:11px;">${escapeHtml(n)}</div>`;
                }
            }
            if (meInfo.me_region_size_formatted) {
                html += `<div style="font-size:11px;color:var(--muted);">Region size: ${escapeHtml(meInfo.me_region_size_formatted)} at offset ${escapeHtml(meInfo.me_region_offset || '0x0')}</div>`;
            }
        }

        if (meInfo && meInfo.notes && meInfo.notes.length && meInfo.found) {
            html += `<div style="margin-top:4px;font-size:11px;">`;
            for (const n of meInfo.notes) {
                html += `<span style="color:#e8b739;">⚠ ${escapeHtml(n)}</span> `;
            }
            html += `</div>`;
        }

        html += `</div></details>`;
    }

    // ── AMI Modules ───────────────────────────────────────────────────────
    if (p && p.ami_modules && p.ami_modules.total_modules) {
        const am = p.ami_modules;
        html += `<details class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">AMI Modules (${am.total_modules}) &mdash; ${am.compressed_count} compressed, ${am.decompressed_ok_count} ok</summary>`;
        html += `<div style="max-height:400px;overflow-y:auto;font-size:12px;">`;
        for (const m of am.modules || []) {
            const sz = m.decompressed_size > 1024 ? (m.decompressed_size / 1024).toFixed(0) + 'K' : m.decompressed_size + 'B';
            const st = m.decompressed_ok ? 'dec' : m.compressed ? 'cmp' : 'raw';
            html += `<div class="flex" style="justify-content:space-between;padding:1px 8px;border-top:1px solid var(--border);">
                <span>${escapeHtml(m.part_id)} ${escapeHtml(m.name)}</span>
                <span class="text-muted">${sz} ${st}</span></div>`;
        }
        html += `</div></details>`;
    }

    // ── SMBIOS ────────────────────────────────────────────────────────────
    if (p && p.smbios_structures && p.smbios_structures.length) {
        html += `<div class="panel" style="margin-top:8px;">`;
        html += `<div class="panel-header">SMBIOS / DMI</div>`;
        html += `<div class="panel-body">`;
        for (const s of p.smbios_structures) {
            html += `<div class="info-grid">`;
            for (const [k, v] of Object.entries(s)) {
                html += `<span class="key">${escapeHtml(k)}</span><span class="value">${escapeHtml(String(v))}</span>`;
            }
            html += `</div>`;
        }
        html += `</div></div>`;
    }

    // ── SMBIOS Tables (raw entry points) ──────────────────────────────────
    if (p && p.smbios_tables && p.smbios_tables.length) {
        html += `<details class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">SMBIOS Entry Points (${p.smbios_tables.length})</summary>`;
        html += `<div style="font-size:11px;padding:2px 8px;">`;
        for (const t of p.smbios_tables) {
            html += `<div class="flex" style="justify-content:space-between;padding:1px 0;font-family:monospace;">
                <span>${escapeHtml(t.version || t.type || '?')}</span>
                <span class="text-muted">@0x${(t.offset||0).toString(16).toUpperCase()} ${t.size ? t.size+'B' : ''}</span>
            </div>`;
        }
        html += `</div></details>`;
    }

    // ── NVRAM (from reset_nvram --json) ──────────────────────────────────
    const nv = data.nvram;
    if (nv && nv.nvram && nv.nvram.detected) {
        const nd = nv.nvram;
        html += `<details open class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">NVRAM — ${nd.formats.join(', ')}</summary>`;
        html += `<div style="font-size:12px;padding:4px 8px;">`;

        if (nd.nvar) {
            html += `<div style="margin-bottom:6px;"><b>NVAR (AMI Aptio V)</b>: ${nd.nvar.variables.toLocaleString()} variables, `;
            html += `region 0x${(nd.nvar.region_start||0).toString(16).toUpperCase()}-0x${(nd.nvar.region_end||0).toString(16).toUpperCase()} `;
            html += `(${(nd.nvar.region_size/1024).toFixed(0)} KB)</div>`;
        }
        if (nd.vss) {
            for (const s of nd.vss) {
                html += `<div style="margin-bottom:4px;"><b>VSS (Insyde H2O)</b>: at 0x${(s.offset||0).toString(16).toUpperCase()}, ${s.size_kb} KB</div>`;
            }
        }
        if (nd.evsa) {
            for (const s of nd.evsa) {
                html += `<div style="margin-bottom:4px;"><b>EVSA (AMI)</b>: at 0x${(s.offset||0).toString(16).toUpperCase()}, ${s.size_kb} KB, ${s.variables} variables</div>`;
            }
        }
        if (nd.dead_zones && nd.dead_zones.length) {
            html += `<div style="margin-bottom:4px;"><b>Dead zones (FPT)</b>: ${nd.dead_zones.length} blocks, ${(nd.dead_zones_total_bytes/1024).toFixed(0)} KB total</div>`;
        }
        html += `</div></details>`;
    } else if (nv && nv.nvram && nv.nvram.note) {
        html += `<div style="padding:4px 8px;font-size:13px;color:var(--muted);">NVRAM: ${escapeHtml(nv.nvram.note)}</div>`;
    }

    // ── Intel FIT (from fit_parser --json) ─────────────────────────────────
    if (fit && fit.found) {
        html += `<details open class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">Intel FIT — ${fit.entries_count} entries</summary>`;
        html += `<div style="font-size:12px;padding:4px 8px;">`;

        // Microcodes
        if (fit.microcodes && fit.microcodes.length) {
            html += `<div style="margin-bottom:4px;"><b>Microcodes (${fit.microcodes.length})</b></div>`;
            html += `<div style="max-height:200px;overflow-y:auto;margin-bottom:8px;">`;
            for (const mc of fit.microcodes) {
                html += `<div class="flex" style="justify-content:space-between;padding:1px 8px;border-top:1px solid var(--border);font-family:monospace;">`;
                html += `<span>CPUID ${mc.cpuid}</span>`;
                html += `<span>Rev ${mc.revision}</span>`;
                html += `<span>${mc.date}</span>`;
                html += `<span class="text-muted">${mc.size_formatted}</span>`;
                html += `</div>`;
            }
            html += `</div>`;
        }

        // ACMs
        if (fit.acms && fit.acms.length) {
            html += `<div style="margin-bottom:4px;"><b>Startup ACMs (${fit.acms.length})</b></div>`;
            for (const acm of fit.acms) {
                html += `<div style="font-family:monospace;padding:1px 8px;">${acm.address} — ${acm.size_bytes.toLocaleString()} B</div>`;
            }
        }

        // Boot Guard
        if (fit.bootguard) {
            const bg = fit.bootguard;
            let bgColor = bg.status === 'structures_found' ? '#e8b739' : bg.status === 'partial' ? '#e8b739' : '#6c6';
            html += `<div style="margin-top:8px;padding:6px 8px;background:var(--panel);border-radius:4px;">`;
            html += `<b>Boot Guard</b>: <span style="color:${bgColor};font-weight:600;">${bg.status.toUpperCase()}</span>`;
            if (bg.has_km) html += ` &middot; KM`;
            if (bg.has_bp) html += ` &middot; BP`;
            if (bg.needs_fpf_check) html += `<br><small class="text-muted">Final status requires PCH fuse check (FPF registers)</small>`;
            if (bg.entries_present && !bg.has_km && !bg.has_bp) html += `<br><small class="text-muted">FIT entries present but structures are empty (not provisioned)</small>`;
            html += `</div>`;
        }

        // All entries (collapsed)
        if (fit.entries && fit.entries.length) {
            html += `<details style="margin-top:6px;"><summary class="text-sm text-muted" style="cursor:pointer;">All FIT entries (${fit.entries.length})</summary>`;
            html += `<div style="max-height:200px;overflow-y:auto;">`;
            for (const e of fit.entries) {
                html += `<div class="flex" style="justify-content:space-between;padding:1px 8px;border-top:1px solid var(--border);font-family:monospace;font-size:11px;">
                    <span>[${e.index}] ${e.type_name}</span>
                    <span>0x${(e.address||0).toString(16).toUpperCase().padStart(16,'0')}</span>
                    <span class="text-muted">${e.checksum_valid ? 'chk ok' : ''}</span></div>`;
            }
            html += `</div></details>`;
        }

        html += `</div></details>`;
    } else if (fit && !fit.found) {
        // FIT checked but not found — tell the technician why
        html += `<div style="padding:4px 8px;font-size:13px;color:var(--muted);margin-bottom:8px;">`;
        html += `Intel FIT: <b>not found</b> — this is normal for non-Intel platforms or older BIOS versions without Boot Guard support`;
        html += `</div>`;
    }

    // ── NVAR Variables (from nvar_parser --json) ───────────────────────────
    const nvar = data.nvar;
    if (nvar && nvar.found && nvar.stores && nvar.stores.length) {
        let totalVars = 0;
        for (const s of nvar.stores) totalVars += (s.variable_count || 0);
        html += `<details class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">NVAR Variables (${totalVars} total, ${nvar.stores.length} stores)</summary>`;
        html += `<div style="max-height:300px;overflow-y:auto;font-size:11px;">`;
        for (const store of nvar.stores) {
            const vars = (store.variables || []).slice(0, 50);
            const guidStr = store.store_guid ? store.store_guid.substring(0,16) + '...' : 'no GUID';
            html += `<div style="margin:4px 0 2px;font-weight:600;color:var(--accent);">Store #${store.index||0} — GUID ${escapeHtml(guidStr)} — ${store.variable_count||0} vars</div>`;
            for (const v of vars) {
                const active = v.state_label === 'active';
                const stateColor = active ? '#6c6' : '#e55';
                const stateLabel = active ? 'OK' : 'DEL';
                const name = v.name || '(unnamed)';
                const guidHex = v.guid || '?';
                const guidShort = guidHex.length > 16 ? guidHex.substring(0, 16) + '...' : guidHex;
                html += `<div class="flex" style="justify-content:space-between;padding:1px 6px;border-top:1px solid var(--border);font-family:monospace;font-size:11px;">
                    <span style="flex:2;">${escapeHtml(name)}</span>
                    <span class="text-muted" style="flex:1;font-size:10px;">${escapeHtml(guidShort)}</span>
                    <span style="color:${stateColor};width:30px;text-align:center;">${stateLabel}</span>
                    <span class="text-muted" style="width:40px;text-align:right;">${v.data_size || 0}B</span>
                </div>`;
            }
            if (store.variable_count > 50) {
                html += `<div class="text-muted" style="padding:2px 6px;">... +${store.variable_count - 50} more variables</div>`;
            }
        }
        html += `</div></details>`;
    }

    // ── Security Audit (NIST SP 800-147) ───────────────────────────────────
    // Always shown when analysis data is available — serwisant needs to see
    // the findings even when nothing was detected (explains WHY).
    if (fd || sb) {
        html += `<details open class="mb-2"><summary class="text-sm" style="font-weight:600;cursor:pointer;padding:4px 0;">Security Audit (NIST 800-147)</summary>`;
        html += `<div style="font-size:12px;padding:4px 8px;">`;

        // ── Flash Descriptor Security ──────────────────────────────────────
        if (fd) {
            const fdColors = {compliant: '#6c6', partial: '#e8b739', non_compliant: '#e55', not_detected: 'var(--muted)'};
            const fdColor = fdColors[fd.status] || 'var(--muted)';
            const fdLabel = fd.status === 'not_detected' ? 'IFD NOT FOUND' : fd.status.toUpperCase();

            html += `<div style="margin-bottom:6px;padding:6px 8px;background:var(--panel);border-radius:4px;">`;
            html += `<b>Flash Descriptor</b>: <span style="color:${fdColor};font-weight:600;">${fdLabel}</span>`;

            if (fd.status === 'not_detected') {
                // Wyjaśnij DLACZEGO nie wykryto
                html += `<br><small class="text-muted">${escapeHtml(fd.summary || 'No Intel Flash Descriptor present')}`;
                html += `<br>This means the dump is likely a <b>BIOS region only</b>, not a full SPI image.`;
                html += `<br>SPI flash write-protection analysis requires a full dump (8–64 MB) with IFD at offset 0x00.</small>`;
            } else {
                // IFD wykryty — pokaż szczegóły
                if (fd.descriptor_locked) {
                    html += ` &middot; <span style="color:#6c6;">Locked ✓</span>`;
                } else {
                    html += ` &middot; <span style="color:#e55;">Unlocked ⚠</span>`;
                }
                if (fd.descriptor_checksum_valid) {
                    html += ` &middot; <span style="color:#6c6;">Checksum OK ✓</span>`;
                } else {
                    html += ` &middot; <span style="color:#e55;">Checksum INVALID ⚠</span>`;
                }

                // Non-bypassability
                if (fd.non_bypassability_pass) {
                    html += `<br><small><span style="color:#6c6;">NIST §4.3 Non-Bypassability: PASS</span> — only CPU can write BIOS region</small>`;
                } else {
                    html += `<br><small><span style="color:#e55;">NIST §4.3 Non-Bypassability: FAIL</span>`;
                    if (fd.bios_writable_by_me) html += ` — ME has write access!`;
                    if (fd.bios_writable_by_ec) html += ` — EC has write access!`;
                    html += `</small>`;
                }

                // Master access table
                if (fd.master_access && fd.master_access.length) {
                    html += `<br><small>`;
                    for (const ma of fd.master_access) {
                        const wm = (ma.write_masters || []).join(', ') || 'none';
                        html += `${ma.region}: write=[${wm}] `;
                    }
                    html += `</small>`;
                }

                // FD Regions (from IFD, different from parse_bios regions)
                if (fd.regions && fd.regions.length) {
                    const populated = fd.regions.filter(r => r.is_populated);
                    if (populated.length) {
                        html += `<br><small><b>IFD Regions:</b> `;
                        html += populated.map(r => `${r.name}: 0x${r.offset}-0x${(r.offset + r.size).toString(16).toUpperCase()} (${r.size_formatted || r.size + 'B'})`).join(', ');
                        html += `</small>`;
                    }
                }

                // FD Components (flash chips)
                if (fd.components && fd.components.length) {
                    html += `<br><small><b>Flash chips:</b> `;
                    html += fd.components.map(c => `${c.density_mb}MB ×${c.number_of_components}`).join(', ');
                    html += ` &middot; Total: ${fd.flash_size ? (fd.flash_size/(1024*1024)).toFixed(0)+' MB' : '?'}</small>`;
                }
            }

            if (fd.issues && fd.issues.length) {
                html += `<br><small style="color:#e8b739;">⚠ ${fd.issues.map(i => escapeHtml(i)).join('; ')}</small>`;
            }
            html += `</div>`;
        }

        // ── SecureBoot ──────────────────────────────────────────────────────
        if (sb) {
            const sbColors = {compliant: '#6c6', partial: '#e8b739', non_compliant: '#e55', not_detected: 'var(--muted)'};
            const sbColor = sbColors[sb.compliance_level] || 'var(--muted)';
            const sbLabel = sb.compliance_level === 'not_detected' ? 'NOT FOUND' : sb.compliance_level.toUpperCase();

            html += `<div style="margin-bottom:6px;padding:6px 8px;background:var(--panel);border-radius:4px;">`;
            html += `<b>SecureBoot</b>: <span style="color:${sbColor};font-weight:600;">${sbLabel}</span>`;

            if (sb.compliance_level === 'not_detected') {
                html += `<br><small class="text-muted">${escapeHtml(sb.summary || 'No UEFI SecureBoot variables detected')}`;
                html += `<br>Possible reasons: non-UEFI BIOS, non-AMI platform, corrupted NVRAM, or dump does not contain NVRAM region.</small>`;
            } else {
                // Tryb platformy
                html += ` &middot; Mode: <b>${sb.platform_mode}</b>`;
                html += ` &middot; SecureBoot: <b>${sb.secure_boot_enabled ? 'ON' : 'OFF'}</b>`;

                // Flagi trybów specjalnych
                if (sb.setup_mode) html += ` &middot; <span style="color:#e8b739;" title="No PK enrolled — SecureBoot cannot be enabled">SetupMode</span>`;
                if (sb.audit_mode) html += ` &middot; <span style="color:#e8b739;" title="Signature checks logged but not enforced">AuditMode</span>`;
                if (sb.deployed_mode) html += ` &middot; <span title="Most restrictive mode — PK updates require physical presence">DeployedMode</span>`;

                // Liczniki kluczy
                const pkCount = (sb.pk || []).reduce((s, sl) => s + (sl.entries_count || 0), 0);
                const kekCount = (sb.kek || []).reduce((s, sl) => s + (sl.entries_count || 0), 0);
                const dbCount = (sb.db || []).reduce((s, sl) => s + (sl.entries_count || 0), 0);
                const dbxCount = (sb.dbx || []).reduce((s, sl) => s + (sl.entries_count || 0), 0);

                html += `<br><small>Keys: PK=<b>${pkCount}</b>, KEK=<b>${kekCount}</b>, db=<b>${dbCount}</b>, dbx=<b>${dbxCount}</b>`;
                if (!sb.x509_available) html += ` &middot; <span class="text-muted">X.509: not available (install cryptography)</span>`;
                html += `</small>`;

                // Szczegóły certyfikatów (jeśli dostępne)
                if (pkCount > 0 || kekCount > 0) {
                    html += `<details style="margin-top:4px;"><summary class="text-muted" style="cursor:pointer;font-size:11px;">Certificate details</summary>`;
                    html += `<div style="max-height:200px;overflow-y:auto;font-size:11px;">`;
                    for (const [label, lists] of [['PK', sb.pk || []], ['KEK', sb.kek || []], ['db', sb.db || []], ['dbx', sb.dbx || []]]) {
                        for (const sl of lists) {
                            for (const e of (sl.entries || [])) {
                                if (e.cert_subject) {
                                    html += `<div style="padding:2px 4px;border-top:1px solid var(--border);">`;
                                    html += `<b>${label}</b> — ${escapeHtml(e.cert_subject)}`;
                                    if (e.cert_issuer) html += `<br>Issuer: ${escapeHtml(e.cert_issuer)}`;
                                    if (e.cert_valid_to) html += ` &middot; Valid to: ${e.cert_valid_to}`;
                                    if (e.cert_key_algorithm) {
                                        html += ` &middot; ${e.cert_key_algorithm}`;
                                        if (e.cert_key_size) html += `-${e.cert_key_size}`;
                                    }
                                    html += `</div>`;
                                }
                            }
                        }
                    }
                    html += `</div></details>`;
                }
            }

            if (sb.issues && sb.issues.length) {
                html += `<br><small style="color:#e8b739;">⚠ ${sb.issues.map(i => escapeHtml(i)).join('; ')}</small>`;
            }
            html += `</div>`;
        }

        html += `</div></details>`;
    }

    // ── Raw JSON (collapsed) ──────────────────────────────────────────────

    // ── Raw JSON (collapsed) ──────────────────────────────────────────────
    if (p) {
        html += `<details style="cursor:pointer;margin-top:8px;"><summary class="text-sm text-muted">Raw JSON</summary>`;
        html += `<pre class="output" style="max-height:300px;overflow-y:auto;font-size:11px;">${escapeHtml(JSON.stringify(p, null, 2))}</pre>`;
        html += `</details>`;
    }

    html += `</div>`; // close analysisSection

    document.getElementById('view-info').insertAdjacentHTML('beforeend', html);
}

// ── Diff ─────────────────────────────────────────────────────────────────────

async function loadDiff() {
    if (!state.selectedFile) { setStatus('Upload a file first', true); return; }
    if (!state.diffFile) { setStatus('Upload a second file for comparison', true); return; }
    const origRel = state.selectedFile.relpath || state.selectedFile.path;
    const repRel = state.diffFile.relpath || state.diffFile.path;
    if (!origRel || !repRel) return;
    const area = document.getElementById('diffContent');
    area.innerHTML = '<div class="loading">Comparing...</div>';
    try {
        const resp = await fetch(`/api/diff/${encodeRelpath(origRel)}/${encodeRelpath(repRel)}`);
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

// ── Fix / Repair ─────────────────────────────────────────────────────────────

async function loadFix() {
    const area = document.getElementById('view-fix');
    area.innerHTML = '<div class="loading">Loading...</div>';
    const relpath = state.selectedFile ? (state.selectedFile.relpath || state.selectedFile.path) : null;
    let html = '';

    // ── Intro: co robi ta zakładka (PL) ──────────────────────────────────
    html += `<div class="panel" style="border-color:var(--border);">
        <div class="panel-header">Naprawa BIOS</div>
        <div class="panel-body text-sm">
            <p style="margin:0 0 6px;">Wszystkie operacje poniżej <b>tworzą nowy plik</b> obok oryginału —
            plik źródłowy nigdy nie jest zmieniany. Po zapisie nowy plik zostanie automatycznie
            wczytany, a zmiany można porównać z oryginałem.</p>
            <p style="margin:0;color:var(--muted);">Działaj na <b>kopii zapasowej</b> dumpu, a przed wgraniem
            na programator zawsze weryfikuj wynik w zakładce <b>Diff</b>.</p>
        </div>
    </div>`;

    // ── Strefa 1: bezpieczne — pojedyncze zmienne ────────────────────────
    html += `<div class="panel" style="margin-top:12px;border-color:var(--ok,#2e8b57);">
        <div class="panel-header">1 · Zmienne NVRAM — podgląd i pojedyncze poprawki</div>
        <div class="panel-body">
            <p class="text-sm text-muted">Przeglądaj zmienne zapisane w BIOS-ie (ustawienia Setup, boot order,
            SecureBoot…) i poprawiaj pojedyncze wartości. Każda zmiana trafia na nową kopię pliku —
            można ją najpierw zasymulować i zobaczyć dokładnie „stara wartość → nowa”.</p>
            <button class="btn small" onclick="switchTab('vars')">Otwórz zmienne NVRAM</button>
        </div>
    </div>`;

    // ── Strefa 2: ryzykowna — reset NVRAM ─────────────────────────────────
    const detected = state.analysisData && state.analysisData.parse && state.analysisData.parse.data
        && state.analysisData.parse.data.nvram_store && state.analysisData.parse.data.nvram_store.detected;
    html += `<div class="panel" style="margin-top:12px;border-color:var(--accent-red,#c0392b);">
        <div class="panel-header">2 · Reset NVRAM do ustawień fabrycznych (ryzykowne)</div>
        <div class="panel-body text-sm">`;
    if (!relpath) {
        html += `<p class="text-sm text-muted">Najpierw wczytaj plik .bin (przeciągnij na lewy panel).</p>`;
    } else if (detected) {
        html += `<p style="margin:0 0 6px;"><b>Kiedy stosować:</b> laptop nie startuje / pętla startowa, obraz
            znika po zmianach w BIOS Setup lub po operacjach na SecureBoot, ustawienia same się psują.</p>
            <p style="margin:0 0 6px;"><b>Co robi:</b> czyści zmienne UEFI (ustawienia, boot order, klucze SecureBoot),
            aby BIOS odtworzył je z wartości fabrycznych przy starcie.</p>
            <p style="margin:0 0 10px;color:var(--muted);"><b>Czego NIE dotyka:</b> DMI (numer seryjny, UUID, licencje),
            region Management Engine, boot block. Plik źródłowy pozostaje bez zmian — powstanie nowy „*_nvram_reset.bin”.</p>
            <button class="btn small" style="background:var(--accent-red);color:#fff;"
                onclick="resetNVRAM('${escapeJs(relpath)}')">Reset NVRAM do ustawień fabrycznych</button>`;
    } else {
        html += `<p class="text-sm text-muted">W tym pliku nie wykryto magazynu NVRAM (NVAR/VSS) —
            sprawdź zakładkę Info. Operacja niedostępna.</p>`;
    }
    html += `</div></div>`;

    // ── Strefa 3: patche (zaawansowane) ───────────────────────────────────
    html += `<div class="panel" style="margin-top:12px;"><div class="panel-header">3 · Patche (dla zaawansowanych)</div><div class="panel-body text-sm">`;
    html += `<p class="text-sm text-muted" style="margin:0 0 8px;">Gotowe, udokumentowane modyfikacje dumpu
        (np. czyszczenie regionu ME). Stosuj tylko gdy wiesz, co robi dany patch.</p>`;
    try {
        const patchesResp = await fetch('/api/patches');
        const patches = await patchesResp.json();
        if (patches && patches.length > 0) {
            html += patches.map(p => `
                <div class="flex" style="justify-content:space-between;align-items:center;padding:6px 0;border-top:1px solid var(--border);">
                    <div>
                        <strong>${escapeHtml(p.name)}</strong>
                        <div class="text-sm text-muted">${formatDate(p.modified)}</div>
                    </div>
                    <button class="btn small" onclick="applyFixPatch('${escapeJs(p.name)}')">Apply</button>
                </div>
            `).join('');
        } else {
            html += `<p class="text-sm text-muted">Brak dostępnych patchy. Dodaj skrypty .py do tools/patches/</p>`;
        }
    } catch (e) {
        html += `<div class="error-state">${e.message}</div>`;
    }
    html += `</div></div>`;

    area.innerHTML = html;
}

async function applyFixPatch(patchName) {
    const relpath = state.selectedFile ? (state.selectedFile.relpath || state.selectedFile.path) : null;
    if (!relpath) { setStatus('Upload a file first', true); return; }
    if (!confirm(`Apply patch "${patchName}" to "${state.selectedFile.name || relpath}"?`)) return;
    setStatus(`Applying patch ${patchName}...`);
    try {
        const resp = await fetch('/api/patch/apply', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({patch: patchName, input: relpath})
        });
        const result = await resp.json();
        if (result.error) {
            setStatus(`Patch failed: ${result.error}`, true);
        } else {
            setStatus(`Patch applied: ${result.output || 'OK'}`);
        }
    } catch (e) {
        setStatus(`Patch error: ${e.message}`, true);
    }
}

// ── NVRAM Reset ──────────────────────────────────────────────────────────────

async function resetNVRAM(relpath) {
    if (!relpath) return;
    if (!confirm(
        'Reset NVRAM do ustawień fabrycznych?\n\n' +
        'Zostaną wyczyszczone zmienne UEFI: ustawienia BIOS Setup, boot order, klucze SecureBoot (PK/KEK/db/dbx).\n\n' +
        'NIE zostaną zmienione: DMI (numer seryjny, UUID, licencje), region ME, boot block.\n\n' +
        'Plik źródłowy pozostaje nietknięty — powstanie nowy plik *_nvram_reset.bin.')) return;
    setStatus('Resetting NVRAM...');
    try {
        const resp = await fetch('/api/nvram/reset', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({relpath: relpath})
        });
        const result = await resp.json();
        if (result.error) {
            setStatus(`NVRAM reset failed: ${result.error}`, true);
        } else {
            setStatus(`NVRAM reset OK: ${(result.cleared_bytes / 1024).toFixed(0)} KB cleared → ${result.repaired_name}`);
            // Fetch and load the repaired file info
            const infoResp = await fetch(`/api/file-info/${encodeRelpath(result.repaired_file)}`);
            const info = await infoResp.json();
            if (!info.error) {
                state.selectedFile = info;
                state.diffFile = null;
                showFileInSidebar(info);
                loadFileInfo(info);
            }
        }
    } catch (e) {
        setStatus(`NVRAM reset error: ${e.message}`, true);
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

function statCard(value, label) {
    return `<div class="stat-card"><div class="value">${escapeHtml(String(value))}</div><div class="label">${escapeHtml(label)}</div></div>`;
}

// ── Zmienne NVRAM (tab "Zmienne", PL, dla laika) ─────────────────────────────

let VAR_ITEMS = [];            // lista zmiennych z /api/var/list
let VAR_FILTER = '';           // aktywny filtr nazwy
let VAR_SELECTED = null;       // wybrana zmienna (row z listy)
let VAR_ORIG_INFO = null;      // oryginalny plik przed zapisem kopii
let VAR_SIM_OK = false;        // czy symulacja przeszła pomyślnie

function numAuto(text) {
    text = String(text == null ? '' : text).trim();
    if (!text) return NaN;
    return /^0x/i.test(text) ? parseInt(text, 16) : parseInt(text, 10);
}

function hexIntStr(value, bytes) {
    let s = BigInt(value).toString(16).toUpperCase();
    const min = bytes ? bytes * 2 : 2;
    while (s.length < min) s = '0' + s;
    return '0x' + s;
}

function hexBytesToIntLE(hexStr) {
    const parts = String(hexStr || '').split(/\s+/).filter(Boolean);
    let v = 0n;
    for (let i = parts.length - 1; i >= 0; i--) v = v * 256n + BigInt(parseInt(parts[i], 16));
    return v;
}

function varRelpath() {
    return state.selectedFile ? (state.selectedFile.relpath || state.selectedFile.path) : null;
}

async function loadVars() {
    const relpath = varRelpath();
    if (!relpath) { setStatus('Najpierw wczytaj plik .bin', true); return; }
    const detail = document.getElementById('varDetail');
    detail.innerHTML = '<div class="loading">Wczytywanie zmiennych…</div>';
    const filterEl = document.getElementById('varFilter');
    if (filterEl) filterEl.value = '';
    VAR_FILTER = '';
    VAR_SELECTED = null;
    VAR_SIM_OK = false;
    try {
        const resp = await fetch(`/api/var/list/${encodeRelpath(relpath)}`);
        const d = await resp.json();
        const header = document.getElementById('varHeader');
        const emptyEl = document.getElementById('varEmpty');
        if (!d.ok) {
            detail.innerHTML = `<div class="error-state">${escapeHtml(d.error || 'Błąd odczytu zmiennych')}</div>`;
            if (header) header.textContent = '';
            if (emptyEl) { emptyEl.classList.remove('hidden'); emptyEl.querySelector('p').textContent = 'Brak magazynu ze zmiennymi (NVAR/VSS/EVSA) lub plik po resecie.';
                emptyEl.querySelector('p').textContent += ' Spróbuj zakładki Fix → reset NVRAM.'; }
            setStatus('Brak magazynu zmiennych NVAR', d.found === false ? false : true);
            return;
        }
        VAR_ITEMS = d.variables || [];
        const fmtNames = { NVAR: 'AMI Aptio V', VSS: 'Insyde H2O', EVSA: 'EVSA' };
        const fmtTxt = (d.formats && d.formats.length)
            ? ' · ' + d.formats.map(f => fmtNames[f] || f).join(' + ')
            : '';
        if (header) {
            header.textContent = `${d.total} zmiennych${fmtTxt}` +
                (d.region_start != null
                    ? ` · region 0x${d.region_start.toString(16).toUpperCase()}–0x${d.region_end.toString(16).toUpperCase()}`
                    : '');
        }
        if (emptyEl) emptyEl.classList.add('hidden');
        detail.innerHTML = '';
        renderVarRows();
    } catch (e) {
        detail.innerHTML = `<div class="error-state">${escapeHtml(e.message)}</div>`;
    }
}

function varFilterRows(q) {
    VAR_FILTER = String(q || '').toLowerCase();
    renderVarRows();
}

function renderVarRows() {
    const tbody = document.getElementById('varRows');
    const emptyEl = document.getElementById('varEmpty');
    if (!tbody) return;
    const rows = VAR_ITEMS.filter(v => !VAR_FILTER || v.name.toLowerCase().indexOf(VAR_FILTER) !== -1);
    if (!rows.length) {
        tbody.innerHTML = '';
        if (emptyEl) emptyEl.classList.remove('hidden');
        return;
    }
    if (emptyEl) emptyEl.classList.add('hidden');
    const seen = {};
    tbody.innerHTML = rows.map(v => {
        seen[v.name] = (seen[v.name] || 0) + 1;
        const dup = seen[v.name] > 1 ? ` <span title="duplikat nazwy — wybrano rekord 0x${v.rec.toString(16).toUpperCase()}">#${seen[v.name]}</span>` : '';
        const active = v.state_label === 'active';
        const status = active
            ? '<span style="color:#2e8b57;font-weight:600;">aktywna</span>'
            : '<span style="color:var(--muted);">usunięta</span>';
        const guid = v.guid ? v.guid.slice(0, 8) + '…' : '?';
        const fmtBadge = v.fmt === 'NVAR' ? '' :
            `<span style="font-size:10px;color:#fff;background:#8a5a2b;border-radius:3px;padding:0 4px;margin-left:5px;vertical-align:1px;">${escapeHtml(v.fmt)}</span>`;
        return `<tr data-rec="${v.rec}" style="border-top:1px solid var(--border);cursor:pointer;" onclick="selectVar(${v.rec})" title="Kliknij: podgląd i edycja (rekord 0x${v.rec.toString(16).toUpperCase()})">
            <td style="padding:5px 10px;font-family:monospace;">${escapeHtml(v.name)}${dup}${fmtBadge}</td>
            <td style="padding:5px 10px;">${status}</td>
            <td style="padding:5px 10px;text-align:right;">${v.data_size} B</td>
            <td style="padding:5px 10px;font-family:monospace;color:var(--muted);">${escapeHtml(guid)}</td>
            <td style="padding:5px 10px;text-align:right;"><button class="btn tiny" onclick="event.stopPropagation();selectVar(${v.rec})">Podgląd</button></td>
        </tr>`;
    }).join('');
}

async function selectVar(rec) {
    const row = VAR_ITEMS.find(v => v.rec === rec);
    if (!row) return;
    VAR_SELECTED = row;
    VAR_SIM_OK = false;
    const detail = document.getElementById('varDetail');
    detail.innerHTML = '<div class="loading">Wczytywanie zawartości…</div>';
    const relpath = varRelpath();
    let hexRows = '';
    let previewNote = '';
    try {
        const r = await fetch(`/api/var/read/${encodeRelpath(relpath)}?name=${encodeURIComponent(row.name)}&rec=${rec}&offset=0&size=${Math.min(row.data_size, 128)}`);
        const rd = await r.json();
        if (rd.error) {
            detail.innerHTML = `<div class="error-state">${escapeHtml(rd.error)}</div>`;
            return;
        }
        const bs = String(rd.raw_hex || '').split(/\s+/).filter(Boolean);
        for (let i = 0; i < bs.length; i += 16) {
            const chunk = bs.slice(i, i + 16);
            const addr = (0).toString(16) + '+' + i.toString(16).toUpperCase().padStart(4, '0');
            const hexPart = chunk.map(x => x.toUpperCase()).join(' ').padEnd(48);
            const asc = chunk.map(x => { const c = parseInt(x, 16); return (c >= 32 && c < 127) ? String.fromCharCode(c) : '.'; }).join('');
            hexRows += `  ${addr}  ${hexPart}  ${asc}\n`;
        }
        if (row.data_size > 128) previewNote = `<p class="text-sm text-muted" style="margin:4px 0 0;">Pokazano pierwsze 128 z ${row.data_size} bajtów.
            <a href="#" onclick="event.preventDefault();jumpToHex(${rd.data_area_start});switchTab('hex');">Zobacz całość w Hex</a></p>`;
    } catch (e) {
        detail.innerHTML = `<div class="error-state">${escapeHtml(e.message)}</div>`;
        return;
    }

    const active = row.state_label === 'active';
    detail.innerHTML = `
    <div class="panel" style="margin-top:12px;">
        <div class="panel-header"><span>Zmienna: <span style="font-family:monospace;">${escapeHtml(row.name)}</span>
            <span style="color:var(--muted);font-size:12px;">rekord 0x${rec.toString(16).toUpperCase()}</span></span>
            <span class="text-sm">${active ? '<span style="color:#2e8b57;">aktywna</span>' : '<span style="color:var(--muted);">usunięta</span>'} · dane: ${row.data_size} B</span>
        </div>
        <div class="panel-body">
            <div class="info-grid" style="margin-bottom:8px;">
                <span class="key">Pełny GUID</span><span class="value" style="font-family:monospace;">${escapeHtml(row.guid || '?')}</span>
                <span class="key">Stan</span><span class="value">${active ? 'aktywna (używana przez BIOS)' : 'usunięta (nieaktywna — BIOS jej nie czyta)'}</span>
            </div>
            <details>
                <summary class="text-sm" style="cursor:pointer;font-weight:600;">Zawartość (pierwsze bajty)</summary>
                <pre class="output" style="margin-top:6px;">${escapeHtml(hexRows)}</pre>${previewNote}
            </details>
            <div style="margin-top:14px;border-top:1px solid var(--border);padding-top:10px;">
                <p class="text-sm" style="margin:0 0 6px;"><b>Edytuj bajty zmiennej</b>
                    <span class="text-muted">(dla zaawansowanych — offset i wartość w hex, np. <code>0x40</code> i <code>0x01</code>)</span></p>
                <div class="flex gap-1" style="align-items:center;flex-wrap:wrap;row-gap:6px;">
                    <label class="text-sm text-muted">offset</label>
                    <input type="text" id="veOffset" value="0x0" style="width:70px;font-family:monospace;">
                    <label class="text-sm text-muted" style="margin-left:8px;">rozmiar</label>
                    <input type="text" id="veSize" value="1" style="width:50px;font-family:monospace;" title="1–8 bajtów (maks. 8 przy zapisie)">
                    <label class="text-sm text-muted" style="margin-left:8px;">nowa wartość</label>
                    <input type="text" id="veValue" placeholder="np. 0x01" style="width:120px;font-family:monospace;">
                    <button class="btn small" onclick="readVarCurrent()">Odczytaj aktualną</button>
                    <button class="btn small" onclick="simulateVarWrite()">Symuluj zmianę</button>
                    <button class="btn small" id="veApplyBtn" disabled style="background:var(--accent-red);color:#fff;"
                        onclick="applyVarWrite()">Zapisz poprawioną kopię</button>
                </div>
                <div id="veCurrent" class="text-sm text-muted" style="margin-top:6px;"></div>
                <div id="veSimBox"></div>
            </div>
        </div>
    </div>`;
    document.getElementById('veApplyBtn').disabled = true;
    const cur = document.getElementById('veCurrent');
    if (cur) cur.textContent = `Aktualnie: ${row.data_size} B danych · zmienna ${active ? 'aktywna' : 'usunięta'}.`;
}

async function readVarCurrent() {
    if (!VAR_SELECTED) return;
    const offset = numAuto(document.getElementById('veOffset').value);
    const size = numAuto(document.getElementById('veSize').value);
    const box = document.getElementById('veCurrent');
    if (isNaN(offset) || offset < 0) { box.textContent = 'Nieprawidłowy offset.'; return; }
    if (isNaN(size) || size < 1 || size > 8) { box.textContent = 'Rozmiar musi być od 1 do 8.'; return; }
    const relpath = varRelpath();
    try {
        const r = await fetch(`/api/var/read/${encodeRelpath(relpath)}?name=${encodeURIComponent(VAR_SELECTED.name)}&rec=${VAR_SELECTED.rec}&offset=${offset}&size=${size}`);
        const d = await r.json();
        if (d.error) { box.textContent = d.error; return; }
        box.textContent = `Aktualna wartość @0x${offset.toString(16).toUpperCase()} (${size} B): ${String(d.raw_hex).toUpperCase()} = ${hexIntStr(hexBytesToIntLE(d.raw_hex), size)} (little-endian)`;
    } catch (e) {
        box.textContent = e.message;
    }
}

function varOpsFromForm() {
    if (!VAR_SELECTED) return { error: 'Nie wybrano zmiennej.' };
    const offset = numAuto(document.getElementById('veOffset').value);
    const size = numAuto(document.getElementById('veSize').value);
    const valueText = String(document.getElementById('veValue').value || '').trim();
    if (isNaN(offset) || offset < 0) return { error: 'Nieprawidłowy offset — użyj liczby, np. 0x40.' };
    if (isNaN(size) || size < 1 || size > 8) return { error: 'Rozmiar musi być liczbą od 1 do 8.' };
    if (!valueText) return { error: 'Podaj nową wartość (np. 0x01).' };
    const valueNum = numAuto(valueText);
    if (isNaN(valueNum) || valueNum < 0) return { error: 'Nieprawidłowa wartość — np. 0x01.' };
    // Dla rozmiaru <= 6 B liczba mieści się w zakresie bezpiecznym JS (2^48 < 2^53);
    // większe wartości waliduje dokładnie backend (Python int), unikamy utraty precyzji.
    if (size <= 6 && valueNum >= Math.pow(2, 8 * size))
        return { error: `Wartość nie mieści się w ${size} bajcie(ach) — maks. 0x${(Math.pow(2, 8 * size) - 1).toString(16).toUpperCase()}.` };
    // wartość wysyłamy jako string — JS nie utrzyma dokładnie 64-bitowych intów
    const valueStr = /^0x/i.test(valueText) ? valueText.toLowerCase().replace(/^0x/, '0x') : String(valueNum);
    return {
        ops: [{ name: VAR_SELECTED.name, rec: VAR_SELECTED.rec, offset: offset, size: size, value: valueStr }],
        offset: offset, size: size,
    };
}

function writePreviewLine(w) {
    const off = w.op.offset;
    const size = w.op.size;
    const oldHex = String(w.old_hex).split(/\s+/).filter(Boolean).join(' ').toUpperCase();
    const newHex = String(w.new_hex).split(/\s+/).filter(Boolean).join(' ').toUpperCase();
    const oldInt = hexIntStr(Number(hexBytesToIntLE(w.old_hex)), size);
    const newInt = hexIntStr(Number(hexBytesToIntLE(w.new_hex)), size);
    return `${escapeHtml(w.op.name)} @0x${w.op.rec.toString(16).toUpperCase()} · offset 0x${off.toString(16).toUpperCase()} · ${size} B: <b>${escapeHtml(oldHex)}</b> (${oldInt}) → <b>${escapeHtml(newHex)}</b> (${newInt})`;
}

async function simulateVarWrite() {
    if (!VAR_SELECTED) return;
    const built = varOpsFromForm();
    const box = document.getElementById('veSimBox');
    const applyBtn = document.getElementById('veApplyBtn');
    if (built.error) { box.innerHTML = `<div class="error-state">${escapeHtml(built.error)}</div>`; applyBtn.disabled = true; return; }
    const relpath = varRelpath();
    box.innerHTML = '<div class="text-sm text-muted">Symulacja…</div>';
    applyBtn.disabled = true;
    VAR_SIM_OK = false;
    try {
        const resp = await fetch('/api/var/write', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ relpath: relpath, ops: built.ops, simulate: true })
        });
        const d = await resp.json();
        if (!d.ok || d.error) {
            box.innerHTML = `<div class="error-state">${escapeHtml(d.error || 'Symulacja nie powiodła się')}</div>`;
            return;
        }
        if (!d.writes || !d.writes.length) {
            box.innerHTML = `<div class="text-sm text-muted">Brak zmian do zapisania (wartość już taka sama).</div>`;
            return;
        }
        box.innerHTML = `<div style="margin-top:8px;padding:8px;border:1px solid var(--border);border-radius:6px;background:rgba(46,139,87,.06);">
            <p class="text-sm" style="margin:0 0 4px;"><b>Zmiana gotowa do zapisu (symulacja OK):</b></p>
            <ul style="margin:0;padding-left:18px;font-size:13px;">${d.writes.map(w => `<li style="margin:2px 0;">${writePreviewLine(w)}</li>`).join('')}</ul>
            <p class="text-sm text-muted" style="margin:6px 0 0;">Po zapisie powstanie nowy plik — oryginał pozostanie bez zmian.</p>
        </div>`;
        VAR_SIM_OK = true;
        applyBtn.disabled = false;
    } catch (e) {
        box.innerHTML = `<div class="error-state">${escapeHtml(e.message)}</div>`;
    }
}

async function applyVarWrite() {
    if (!VAR_SELECTED || !VAR_SIM_OK) { setStatus('Najpierw wykonaj symulację zmiany', true); return; }
    const built = varOpsFromForm();
    if (built.error) { setStatus(built.error, true); return; }
    const relpath = varRelpath();
    if (!relpath) return;
    const fileName = state.selectedFile ? state.selectedFile.name : relpath;
    if (!confirm(
        `Zapisać poprawioną kopię pliku?\n\n` +
        `Zmiana: offset 0x${built.offset.toString(16).toUpperCase()}, rozmiar ${built.size} B.\n\n` +
        `Powstanie nowy plik „${fileName.replace(/\.bin$/i, '')}_varedit.bin” — oryginał NIE zostanie zmieniony.\n` +
        `Uwaga: źle dobrana wartość może uniemożliwić start płyty. Zawsze weryfikuj wynik w zakładce Diff.`)) return;
    setStatus('Zapisywanie poprawionej kopii…');
    try {
        const resp = await fetch('/api/var/write', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ relpath: relpath, ops: built.ops, simulate: false })
        });
        const d = await resp.json();
        const box = document.getElementById('veSimBox');
        if (!d.ok || d.error) {
            box.innerHTML = `<div class="error-state">${escapeHtml(d.error || 'Zapis nie powiódł się')}</div>`;
            setStatus('Zapis nie powiódł się', true);
            return;
        }
        VAR_ORIG_INFO = state.selectedFile;
        box.innerHTML = `<div style="margin-top:8px;padding:10px;border:1px solid #2e8b57;border-radius:6px;background:rgba(46,139,87,.08);">
            <p style="margin:0 0 4px;"><b>Utworzono nowy plik:</b> ${escapeHtml(d.output_name || '?')}
                <span class="text-sm text-muted">· zmieniono ${d.changed_bytes} bajtów${d.crc_updated ? ' · CRC32 NVRAM zaktualizowany' : ''}</span></p>
            <p class="text-sm text-muted" style="margin:0 0 8px;">SHA256: <code>${escapeHtml(d.output_sha256 || '')}</code> · oryginał nietknięty.</p>
            <div class="flex gap-1">
                <button class="btn small" onclick="compareVarOutput()">Porównaj z oryginałem (Diff)</button>
                <button class="btn small" onclick="document.getElementById('varDetail').innerHTML=''">Zamknij</button>
            </div>
        </div>`;
        setStatus(`Utworzono: ${d.output_name} (${d.changed_bytes} B zmienionych)`);
        // automatycznie wczytaj nowy plik (jak po reset NVRAM)
        const infoResp = await fetch(`/api/file-info/${encodeRelpath(d.output_relpath)}`);
        const info = await infoResp.json();
        if (!info.error) {
            state.diffFile = VAR_ORIG_INFO;      // oryginał zostaje jako plik porównawczy
            state.selectedFile = info;
            showFileInSidebar(info);
            loadFileInfo(info);
        }
    } catch (e) {
        document.getElementById('veSimBox').innerHTML = `<div class="error-state">${escapeHtml(e.message)}</div>`;
        setStatus(e.message, true);
    }
}

function compareVarOutput() {
    // state.selectedFile = nowa kopia (Diff „original”), state.diffFile = oryginał (Diff „repaired”)
    if (!state.selectedFile || !state.diffFile) { setStatus('Brak plików do porównania', true); return; }
    switchTab('diff');
    loadDiff();
}
