/**
 * GRC Threat Modeler — Dashboard Application
 */

let selectedFile = null;
let analysisResult = null;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dom = {
    dropzone: $('#dropzone'), fileInput: $('#file-input'), fileInfo: $('#file-info'),
    fileName: $('#file-name'), fileSize: $('#file-size'), fileRemove: $('#file-remove'),
    frameworkSelect: $('#framework-select'), profileSelect: $('#profile-select'),
    analyzeBtn: $('#analyze-btn'), sampleButtons: $('#sample-buttons'),
    uploadSection: $('#upload-section'), resultsSection: $('#results-section'),
    backBtn: $('#back-btn'), exportBtn: $('#export-btn'),
    toast: $('#toast'), toastMessage: $('#toast-message'),
    drawerOverlay: $('#drawer-overlay'), drawer: $('#finding-drawer'), drawerClose: $('#drawer-close'),
};

document.addEventListener('DOMContentLoaded', () => {
    setupDropzone(); setupFileInput(); setupButtons(); setupDrawer();
    setupTheme(); loadProfiles(); loadSamples(); setupFilters();
});

// ── Dropzone ──
function setupDropzone() {
    dom.dropzone.addEventListener('click', () => dom.fileInput.click());
    dom.dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dom.dropzone.classList.add('drag-over'); });
    dom.dropzone.addEventListener('dragleave', () => dom.dropzone.classList.remove('drag-over'));
    dom.dropzone.addEventListener('drop', (e) => { e.preventDefault(); dom.dropzone.classList.remove('drag-over'); if (e.dataTransfer.files.length) handleFileSelect(e.dataTransfer.files[0]); });
}
function setupFileInput() {
    dom.fileInput.addEventListener('change', (e) => { if (e.target.files.length) handleFileSelect(e.target.files[0]); });
    dom.fileRemove.addEventListener('click', () => { selectedFile = null; dom.fileInfo.classList.add('hidden'); dom.dropzone.classList.remove('hidden'); dom.analyzeBtn.disabled = true; dom.fileInput.value = ''; });
}
function handleFileSelect(file) {
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!['.csv','.json','.xlsx','.pdf'].includes(ext)) { showToast('Unsupported format: ' + ext); return; }
    selectedFile = file;
    dom.fileName.textContent = file.name;
    dom.fileSize.textContent = formatBytes(file.size);
    dom.fileInfo.classList.remove('hidden');
    dom.dropzone.classList.add('hidden');
    dom.analyzeBtn.disabled = false;
}

// ── Buttons ──
function setupButtons() {
    dom.analyzeBtn.addEventListener('click', () => { if (selectedFile) runAnalysis(); });
    dom.backBtn.addEventListener('click', () => { dom.resultsSection.classList.add('hidden'); dom.uploadSection.classList.remove('hidden'); window.scrollTo({top:0,behavior:'smooth'}); });
    dom.exportBtn.addEventListener('click', exportJSON);
}

// ── Profiles & Samples ──
async function loadProfiles() {
    try { const res = await fetch('/api/profiles'); const data = await res.json();
        data.profiles.forEach(p => { const opt = document.createElement('option'); opt.value = p.filename; opt.textContent = p.name; dom.profileSelect.appendChild(opt); });
    } catch(e) { console.error('Failed to load profiles:', e); }
}
async function loadSamples() {
    try { const res = await fetch('/api/sample-reports'); const data = await res.json();
        dom.sampleButtons.innerHTML = '';
        data.samples.forEach(s => {
            const btn = document.createElement('button'); btn.className = 'sample-btn';
            btn.innerHTML = `<span class="sample-btn-name">${s.filename}</span><span class="sample-btn-fw">${s.framework.toUpperCase()}</span>`;
            btn.addEventListener('click', () => runSampleAnalysis(s)); dom.sampleButtons.appendChild(btn);
        });
    } catch(e) { console.error('Failed to load samples:', e); }
}

// ── Analysis ──
async function runAnalysis() {
    setLoading(true);
    const formData = new FormData();
    formData.append('file', selectedFile); formData.append('framework', dom.frameworkSelect.value); formData.append('profile', dom.profileSelect.value);
    try { const res = await fetch('/api/analyze', {method:'POST', body:formData}); const data = await res.json();
        if (!res.ok) { showToast(data.error || 'Analysis failed'); return; }
        analysisResult = data.result; renderResults(analysisResult);
    } catch(e) { showToast('Network error: '+e.message); } finally { setLoading(false); }
}
async function runSampleAnalysis(sample) {
    setLoading(true); dom.frameworkSelect.value = sample.framework;
    try { const res = await fetch('/api/analyze-sample', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({filename:sample.filename, framework:sample.framework, profile:dom.profileSelect.value})});
        const data = await res.json(); if (!res.ok) { showToast(data.error||'Analysis failed'); return; }
        analysisResult = data.result; renderResults(analysisResult);
    } catch(e) { showToast('Network error: '+e.message); } finally { setLoading(false); }
}
function setLoading(loading) {
    const t = dom.analyzeBtn.querySelector('.btn-text'), l = dom.analyzeBtn.querySelector('.btn-loader');
    dom.analyzeBtn.disabled = loading;
    t.classList.toggle('hidden', loading); l.classList.toggle('hidden', !loading);
}

// ── Render Results ──
function renderResults(r) {
    dom.uploadSection.classList.add('hidden'); dom.resultsSection.classList.remove('hidden');
    window.scrollTo({top:0,behavior:'smooth'});
    ensureScoreGradient();
    const score = r.overall_compliance_score;
    const circ = 2*Math.PI*52, offset = circ*(1-score/100);
    const ring = $('#score-ring-fill');
    ring.style.strokeDasharray = circ; ring.style.strokeDashoffset = circ;
    requestAnimationFrame(()=>requestAnimationFrame(()=>{ ring.style.strokeDashoffset = offset; }));
    const scoreEl = $('#score-value');
    scoreEl.textContent = score.toFixed(1);
    scoreEl.style.color = score>=70?'#2ed573':score>=40?'#ffa502':'#ff4757';
    $('#score-profile').textContent = r.profile_name;
    animateCounter('#total-controls', r.total_controls_analyzed);
    animateCounter('#total-gaps', r.total_gaps);
    animateCounter('#critical-count', r.critical_findings_count);
    animateCounter('#high-count', r.high_findings_count);
    renderExecSummary(r.executive_summary);
    renderTierBreakdown(r.tier_summaries); renderRoadmap(r.roadmap);
    renderDonutChart(r); renderFindings(r.findings); renderAttack(r.threat_exposures, r.attack_coverage);
    $$('#results-section .card').forEach((c,i) => { c.classList.add('animate-in'); c.style.animationDelay=`${i*0.08}s`; });
}

function ensureScoreGradient() {
    if ($('#score-gradient')) return;
    const svg = document.querySelector('.score-ring'); if (!svg) return;
    const defs = document.createElementNS('http://www.w3.org/2000/svg','defs');
    defs.innerHTML = `<linearGradient id="score-gradient" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#6C5CE7"/><stop offset="100%" stop-color="#00D2FF"/></linearGradient>`;
    svg.prepend(defs);
}

// ── Donut Chart ──
function renderDonutChart(r) {
    const svg = $('#status-donut'); const legend = $('#donut-legend');
    svg.innerHTML = ''; legend.innerHTML = '';
    let impl=0, partial=0, missing=0, na=0;
    // Count from tier summaries
    Object.values(r.tier_summaries||{}).forEach(t => { impl+=t.implemented; partial+=t.partial; missing+=t.missing; });
    na = r.total_controls_analyzed - impl - partial - missing;
    const total = impl+partial+missing+(na>0?na:0);
    if (!total) return;
    const segments = [
        {label:'Implemented',count:impl,color:'#00D2FF'},
        {label:'Partial',count:partial,color:'#ffa502'},
        {label:'Missing',count:missing,color:'#ff4757'},
    ];
    if (na>0) segments.push({label:'N/A',count:na,color:'#5a5e78'});
    const r2=44, cx=60, cy=60, circ=2*Math.PI*r2;
    let cumulative=0;
    segments.forEach(s => {
        if (!s.count) return;
        const pct = s.count/total;
        const circle = document.createElementNS('http://www.w3.org/2000/svg','circle');
        circle.setAttribute('cx',cx); circle.setAttribute('cy',cy); circle.setAttribute('r',r2);
        circle.setAttribute('fill','none'); circle.setAttribute('stroke',s.color); circle.setAttribute('stroke-width','14');
        circle.setAttribute('stroke-dasharray',`${pct*circ} ${circ}`);
        circle.setAttribute('stroke-dashoffset',`${-cumulative*circ}`);
        svg.appendChild(circle);
        cumulative += pct;
    });
    // Center text
    const txt = document.createElementNS('http://www.w3.org/2000/svg','text');
    txt.setAttribute('x',cx); txt.setAttribute('y',cy+2); txt.setAttribute('text-anchor','middle');
    txt.setAttribute('dominant-baseline','middle'); txt.setAttribute('fill','#e8eaf6');
    txt.setAttribute('font-size','16'); txt.setAttribute('font-weight','800');
    txt.setAttribute('transform',`rotate(90 ${cx} ${cy})`);
    txt.textContent = total;
    svg.appendChild(txt);
    segments.forEach(s => {
        if (!s.count) return;
        legend.innerHTML += `<div class="donut-legend-item"><span class="donut-legend-dot" style="background:${s.color}"></span>${s.label}: <span class="donut-legend-count">${s.count}</span></div>`;
    });
}

// ── Tier Breakdown ──
function renderTierBreakdown(tiers) {
    const body = $('#tier-body'); body.innerHTML = '';
    const order=['REQUIRED','DESIRED','NICE_TO_HAVE'];
    const colors={REQUIRED:'var(--tier-required)',DESIRED:'var(--tier-desired)',NICE_TO_HAVE:'var(--tier-nice)'};
    order.forEach(n => {
        const t = tiers[n]; if (!t) return;
        const total=t.total_controls, pct=t.compliance_percentage;
        const iW=total?(t.implemented/total*100):0, pW=total?(t.partial/total*100):0, mW=total?(t.missing/total*100):0;
        const row = document.createElement('div'); row.className='tier-row';
        row.innerHTML = `<span class="tier-label" style="color:${colors[n]}">${n.replace('_',' ')}</span>
            <div class="tier-bar-wrap"><div class="tier-bar-segment implemented" style="width:${iW}%"></div><div class="tier-bar-segment partial" style="width:${pW}%"></div><div class="tier-bar-segment missing" style="width:${mW}%"></div></div>
            <span class="tier-pct" style="color:${pct>=70?'#2ed573':pct>=40?'#ffa502':'#ff4757'}">${pct}%</span>`;
        body.appendChild(row);
    });
    if (!body.children.length) body.innerHTML='<p style="color:var(--text-muted);text-align:center;padding:1rem">No tier data</p>';
}

// ── Roadmap ──
function renderRoadmap(roadmap) {
    const body = $('#roadmap-body'); body.innerHTML = '';
    [{key:'P1 - Critical',color:'var(--critical)',label:'P1 Critical'},{key:'P2 - High',color:'var(--high)',label:'P2 High'},{key:'P3 - Medium',color:'var(--medium)',label:'P3 Medium'},{key:'P4 - Low',color:'var(--low)',label:'P4 Low'}].forEach(p => {
        const count = roadmap[p.key]||0;
        body.innerHTML += `<div class="roadmap-row"><span class="roadmap-label"><span class="roadmap-dot" style="background:${p.color}"></span>${p.label}</span><span class="roadmap-count" style="color:${count>0?p.color:'var(--text-muted)'}">${count}</span></div>`;
    });
}

// ── Findings Table ──
function renderFindings(findings) {
    const tbody = $('#findings-tbody'); tbody.innerHTML = '';
    findings.forEach((f,i) => {
        const tr = document.createElement('tr');
        tr.dataset.tier = f.tier; tr.dataset.priority = f.remediation_priority; tr.dataset.index = i;
        const sc = f.status==='Missing'?'badge-missing':'badge-partial';
        const tc = f.tier==='REQUIRED'?'badge-required':f.tier==='DESIRED'?'badge-desired':'badge-nice';
        const pc = f.remediation_priority.startsWith('P1')?'badge-p1':f.remediation_priority.startsWith('P2')?'badge-p2':f.remediation_priority.startsWith('P3')?'badge-p3':'badge-p4';
        const techs = (f.exposed_techniques||[]).slice(0,3).map(t=>`<span class="tech-tag">${t}</span>`).join('') + ((f.exposed_techniques||[]).length>3?`<span class="tech-tag">+${f.exposed_techniques.length-3}</span>`:'');
        tr.innerHTML = `<td>${i+1}</td><td style="font-weight:600;color:var(--text-primary)">${f.control_id}</td><td>${f.control_name}</td>
            <td><span class="badge ${sc}">${f.status}</span></td><td><span class="badge ${tc}">${f.tier.replace('_',' ')}</span></td>
            <td>${f.severity||'Medium'}</td><td class="td-score">${f.weighted_score}</td>
            <td><span class="badge ${pc}">${f.remediation_priority}</span></td><td><div class="tech-tags">${techs}</div></td>`;
        tr.addEventListener('click', () => openDrawer(f));
        tbody.appendChild(tr);
    });
}

// ── Filters ──
function setupFilters() {
    $('#findings-tier-filter').addEventListener('change', applyFilters);
    $('#findings-priority-filter').addEventListener('change', applyFilters);
}
function applyFilters() {
    const tier=$('#findings-tier-filter').value, prio=$('#findings-priority-filter').value;
    $$('#findings-tbody tr').forEach(tr => { tr.style.display = (!tier||tr.dataset.tier===tier)&&(!prio||tr.dataset.priority===prio)?'':'none'; });
}

// ── ATT&CK ──
function renderAttack(exposures, coverage) {
    $('#attack-count').textContent = `${exposures?exposures.length:0} techniques`;
    renderHeatmap(exposures);
    const barsEl = $('#attack-tactic-bars'); barsEl.innerHTML = '';
    if (coverage) {
        Object.entries(coverage).sort((a,b)=>a[1]-b[1]).forEach(([tactic,pct]) => {
            const color = pct>=80?'#2ed573':pct>=50?'#ffa502':'#ff4757';
            barsEl.innerHTML += `<div class="tactic-bar-item"><div class="tactic-bar-header"><span class="tactic-bar-name">${formatTactic(tactic)}</span><span class="tactic-bar-pct">${pct}%</span></div><div class="tactic-bar-track"><div class="tactic-bar-fill" style="width:${pct}%;background:${color}"></div></div></div>`;
        });
    }
    const tbody = $('#attack-tbody'); tbody.innerHTML = '';
    if (exposures) {
        exposures.forEach(e => {
            const rc = `badge-risk-${e.risk_level.toLowerCase()}`;
            tbody.innerHTML += `<tr><td><span style="font-weight:600;color:var(--text-primary)">${e.technique_id}</span>${e.technique_name?`<br><span style="font-size:0.75rem;color:var(--text-muted)">${e.technique_name}</span>`:''}</td>
                <td>${(e.tactics||[]).map(formatTactic).join(', ')}</td><td><span class="badge ${rc}">${e.risk_level}</span></td><td>${e.exposure_count} gap${e.exposure_count!==1?'s':''}</td></tr>`;
        });
    }
}

// ── Detail Drawer ──
function setupDrawer() {
    dom.drawerClose.addEventListener('click', closeDrawer);
    dom.drawerOverlay.addEventListener('click', closeDrawer);
    document.addEventListener('keydown', (e) => { if (e.key==='Escape') closeDrawer(); });
}

function openDrawer(finding) {
    $('#drawer-control-id').textContent = finding.control_id;
    $('#drawer-control-name').textContent = finding.control_name;

    // Badges
    const badges = $('#drawer-badges');
    const sc = finding.status==='Missing'?'badge-missing':'badge-partial';
    const tc = finding.tier==='REQUIRED'?'badge-required':finding.tier==='DESIRED'?'badge-desired':'badge-nice';
    const pc = finding.remediation_priority.startsWith('P1')?'badge-p1':finding.remediation_priority.startsWith('P2')?'badge-p2':finding.remediation_priority.startsWith('P3')?'badge-p3':'badge-p4';
    badges.innerHTML = `<span class="badge ${sc}">${finding.status}</span><span class="badge ${tc}">${finding.tier.replace('_',' ')}</span><span class="badge ${pc}">${finding.remediation_priority}</span>`;

    // Score breakdown
    const sg = $('#drawer-score-grid');
    sg.innerHTML = `
        <div class="drawer-score-item"><div class="drawer-score-value">${finding.severity_score}</div><div class="drawer-score-label">Severity</div></div>
        <div class="drawer-score-item"><div class="drawer-score-value">${finding.gap_factor}</div><div class="drawer-score-label">Gap Factor</div></div>
        <div class="drawer-score-item"><div class="drawer-score-value" style="color:var(--accent-light)">${finding.weighted_score}</div><div class="drawer-score-label">Final Score</div></div>`;

    // Notes
    const notesSection = $('#drawer-notes-section');
    if (finding.notes) { notesSection.classList.remove('hidden'); $('#drawer-notes').textContent = finding.notes; }
    else { notesSection.classList.add('hidden'); }

    // ATT&CK
    const attackSection = $('#drawer-attack-section');
    const attackList = $('#drawer-attack-list');
    if (finding.exposed_techniques && finding.exposed_techniques.length) {
        attackSection.classList.remove('hidden');
        attackList.innerHTML = finding.exposed_techniques.map(t => `<span class="drawer-attack-tag">${t}</span>`).join('');
    } else { attackSection.classList.add('hidden'); }

    // Remediation
    const remSection = $('#drawer-remediation-section');
    const remBody = $('#drawer-remediation');
    const recs = finding.recommendations;
    if (recs && recs.recommendations && recs.recommendations.length) {
        remSection.classList.remove('hidden');
        let html = '';
        if (recs.title) {
            html += `<div class="remediation-title-row"><span class="remediation-title-icon">&#9881;</span><span class="remediation-title-text">${recs.title}</span></div>`;
        }
        if (recs.estimated_effort || recs.estimated_timeline) {
            html += '<div class="remediation-meta">';
            if (recs.estimated_effort) html += `<div class="remediation-meta-item"><span class="remediation-meta-label">Effort:</span><span class="remediation-meta-value">${recs.estimated_effort}</span></div>`;
            if (recs.estimated_timeline) html += `<div class="remediation-meta-item"><span class="remediation-meta-label">Timeline:</span><span class="remediation-meta-value">${recs.estimated_timeline}</span></div>`;
            html += '</div>';
        }
        html += '<ul class="remediation-steps">';
        recs.recommendations.forEach((r,i) => { html += `<li class="remediation-step"><span class="remediation-step-num">${i+1}</span><span>${r}</span></li>`; });
        html += '</ul>';
        if (recs.quick_wins && recs.quick_wins.length) {
            html += '<div class="quick-wins-section"><div class="quick-wins-title">&#9889; Quick Wins</div>';
            recs.quick_wins.forEach(q => { html += `<div class="quick-win-item">${q}</div>`; });
            html += '</div>';
        }
        remBody.innerHTML = html;
    } else { remSection.classList.add('hidden'); }

    // Show drawer
    dom.drawerOverlay.classList.remove('hidden');
    dom.drawer.classList.remove('hidden');
    requestAnimationFrame(() => { dom.drawerOverlay.classList.add('show'); dom.drawer.classList.add('show'); });
}

function closeDrawer() {
    dom.drawerOverlay.classList.remove('show'); dom.drawer.classList.remove('show');
    setTimeout(() => { dom.drawerOverlay.classList.add('hidden'); dom.drawer.classList.add('hidden'); }, 350);
}

// ── Export ──
function exportJSON() {
    if (!analysisResult) return;
    const blob = new Blob([JSON.stringify(analysisResult,null,2)],{type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = `gap_analysis_${new Date().toISOString().slice(0,10)}.json`;
    a.click(); URL.revokeObjectURL(a.href); showToast('JSON exported successfully');
}

// ── Helpers ──
function formatBytes(b) { return b<1024?b+' B':b<1048576?(b/1024).toFixed(1)+' KB':(b/1048576).toFixed(1)+' MB'; }
function formatTactic(t) { return t.replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase()); }
function showToast(msg) {
    dom.toastMessage.textContent = msg; dom.toast.classList.remove('hidden'); dom.toast.classList.add('show');
    setTimeout(()=>{ dom.toast.classList.remove('show'); setTimeout(()=>dom.toast.classList.add('hidden'),400); },3000);
}

// ── Animated Counters ──
function animateCounter(selector, target) {
    const el = $(selector); if (!el) return;
    const duration = 800;
    const start = performance.now();
    const step = (now) => {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(eased * target);
        if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}

// ── Theme Toggle ──
function setupTheme() {
    const saved = localStorage.getItem('grc-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
    updateThemeIcons();
    const btn = $('#theme-toggle');
    if (btn) btn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('grc-theme', next);
        updateThemeIcons();
    });
}
function updateThemeIcons() {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const dark = $('#theme-icon-dark'), light = $('#theme-icon-light');
    if (dark) dark.classList.toggle('hidden', isLight);
    if (light) light.classList.toggle('hidden', !isLight);
}

// ── Executive Summary ──
function renderExecSummary(es) {
    if (!es) return;
    // Posture badge
    const badge = $('#posture-badge');
    badge.textContent = es.posture_rating;
    badge.className = 'card-badge posture-' + es.posture_rating.toLowerCase();
    // Maturity gauge
    const mat = es.maturity || {};
    const matEl = $('#exec-maturity');
    let bars = '';
    for (let i = 1; i <= 5; i++) bars += `<div class="maturity-bar ${i <= mat.level ? 'active' : ''}"></div>`;
    matEl.innerHTML = `<div class="maturity-gauge">${bars}</div>
        <div class="maturity-text">
            <div class="maturity-level">Maturity Level ${mat.level}/5</div>
            <div class="maturity-label">${mat.label}</div>
            <div class="maturity-desc">${mat.description}</div>
        </div>`;
    // Assessment
    $('#exec-assessment').textContent = es.overall_assessment;
    // Key findings
    const findingsEl = $('#exec-findings');
    findingsEl.innerHTML = (es.key_findings||[]).map(f => `<div class="exec-finding-item"><span class="exec-finding-bullet"></span><span>${f}</span></div>`).join('');
    // Risk exposure
    const riskEl = $('#exec-risk');
    if (es.risk_exposure) {
        riskEl.innerHTML = `<div class="exec-risk-title">Threat Exposure</div>${es.risk_exposure}`;
        riskEl.style.display = '';
    } else { riskEl.style.display = 'none'; }
    // Recommendations
    const recsEl = $('#exec-recs');
    recsEl.innerHTML = '<div class="exec-recs-title">Recommended Actions</div>' +
        (es.recommendations_summary||[]).map((r,i) => `<div class="exec-rec-item"><span class="exec-rec-num">${i+1}</span><span>${r}</span></div>`).join('');
}

// ── ATT&CK Heatmap ──
function renderHeatmap(exposures) {
    let container = $('#attack-heatmap');
    if (!container) {
        container = document.createElement('div');
        container.id = 'attack-heatmap'; container.className = 'attack-heatmap';
        const barsEl = $('#attack-tactic-bars');
        if (barsEl) barsEl.parentNode.insertBefore(container, barsEl);
    }
    container.innerHTML = '';
    if (!exposures || !exposures.length) return;
    exposures.forEach(e => {
        const cls = 'heat-' + e.risk_level.toLowerCase();
        const cell = document.createElement('div');
        cell.className = `heatmap-cell ${cls}`;
        cell.title = `${e.technique_id}: ${e.technique_name || ''} (${e.risk_level})`;
        cell.innerHTML = `<span class="heatmap-cell-id">${e.technique_id}</span>${e.technique_name ? `<span class="heatmap-cell-name">${e.technique_name}</span>` : ''}`;
        container.appendChild(cell);
    });
}
