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
function renderAnalysisIntoInfo(data) {
    const p = (data.parse && data.parse.data) ? data.parse.data : null;
    const fit = data.fit;
    let html = '';

    // Remove any previous analysis section
    const prev = document.getElementById('analysisSection');
    if (prev) prev.remove();

    html += `<div id="analysisSection" style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border);">`;

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
    }

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
    let html = '';

    // ── NVRAM Reset ───────────────────────────────────────────────────────
    const p = state.analysisData ? ((state.analysisData.parse && state.analysisData.parse.data) ? state.analysisData.parse.data : null) : null;
    const relpath = state.selectedFile ? (state.selectedFile.relpath || state.selectedFile.path) : null;

    html += `<div class="panel"><div class="panel-header">NVRAM Reset</div><div class="panel-body">`;
    if (relpath && p && p.nvram_store && p.nvram_store.detected) {
        const nv = p.nvram_store;
        html += `<p class="text-sm">Detected ${nv.nvars_found} NVAR entries at 0x${(nv.region_start||0).toString(16).toUpperCase()}</p>`;
        html += `<p class="text-sm text-muted">Clears corrupted UEFI variables to factory defaults. Preserves DMI (serial, UUID, license) and boot block.</p>`;
        html += `<button class="btn small" style="background:var(--accent-red);color:#fff;"
            onclick="resetNVRAM('${escapeJs(relpath)}')">Reset NVRAM to Defaults</button>`;
    } else if (!relpath) {
        html += `<p class="text-sm text-muted">Upload a BIOS file first to check for NVRAM.</p>`;
    }
    html += `</div></div>`;

    // ── Patches ────────────────────────────────────────────────────────────
    try {
        const patchesResp = await fetch('/api/patches');
        const patches = await patchesResp.json();
        html += `<div class="panel" style="margin-top:12px;"><div class="panel-header">Patches</div><div class="panel-body">`;
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
            html += `<p class="text-sm text-muted">No patches available. Add .py scripts to tools/patches/</p>`;
        }
        html += `</div></div>`;
    } catch (e) {
        html += `<div class="error-state">${e.message}</div>`;
    }

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
    if (!confirm('Reset NVRAM to factory defaults?\n\nThis will clear all UEFI variables (settings, boot order, SecureBoot keys).\nBoot block and DMI (serial, UUID, license) will NOT be modified.\n\nA new file *_nvram_reset.bin will be created.')) return;
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
