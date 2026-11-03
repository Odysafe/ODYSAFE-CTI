const DRAFT_STORAGE_KEY = 'flint_draft';
const WORKSPACE_API = '/flash-report/workspaces';
let serverReportsCache = [];
const TOTAL_SECTIONS = 13;
let currentBlock = 1;
let importSourceMap = new Map();

const FR_REMOVE_CELL = '<td class="fr-table-actions"><button type="button" class="btn-remove" onclick="this.closest(\'tr\').remove(); updateFieldStatus();" aria-label="Remove row">×</button></td>';

const PRODUCT_SECTION_PROFILE = {
    'Intelligence Workspace': {
        required: ['block-1', 'block-2', 'block-4', 'block-12', 'block-13'],
        recommended: ['block-3', 'block-6', 'block-7', 'block-9', 'block-11']
    },
    'Flash Threat Alert': {
        required: ['block-1', 'block-2', 'block-3', 'block-4', 'block-9', 'block-13'],
        recommended: ['block-7', 'block-8', 'block-11', 'block-12']
    },
    'Threat Alert': {
        required: ['block-1', 'block-2', 'block-3', 'block-4', 'block-7', 'block-9', 'block-12', 'block-13'],
        recommended: ['block-6', 'block-8', 'block-11']
    },
    'Vulnerability Intelligence Alert': {
        required: ['block-1', 'block-2', 'block-3', 'block-9', 'block-11', 'block-12', 'block-13'],
        recommended: ['block-4', 'block-7', 'block-8', 'block-10']
    },
    'Infrastructure Alert': {
        required: ['block-1', 'block-2', 'block-3', 'block-7', 'block-9', 'block-12', 'block-13'],
        recommended: ['block-4', 'block-6', 'block-8']
    },
    'Hunt Lead': {
        required: ['block-1', 'block-2', 'block-4', 'block-8', 'block-13'],
        recommended: ['block-6', 'block-7', 'block-10', 'block-12']
    },
    'Detection Package': {
        required: ['block-1', 'block-2', 'block-6', 'block-8', 'block-12', 'block-13'],
        recommended: ['block-4', 'block-7', 'block-9', 'block-10']
    },
    'Incident Intelligence Support': {
        required: ['block-1', 'block-2', 'block-3', 'block-4', 'block-5', 'block-7', 'block-9', 'block-12', 'block-13'],
        recommended: ['block-6', 'block-8', 'block-10', 'block-11']
    },
    'Investigation Update': {
        required: ['block-1', 'block-2', 'block-3', 'block-4', 'block-5', 'block-10', 'block-12', 'block-13'],
        recommended: ['block-7', 'block-8', 'block-9', 'block-11']
    },
    'Technical Intelligence Report': {
        required: ['block-1', 'block-2', 'block-4', 'block-6', 'block-7', 'block-12', 'block-13'],
        recommended: ['block-5', 'block-8', 'block-10', 'block-11']
    },
    'Final Intelligence Assessment': {
        required: ['block-1', 'block-2', 'block-3', 'block-4', 'block-5', 'block-10', 'block-11', 'block-12', 'block-13'],
        recommended: ['block-6', 'block-7', 'block-8', 'block-9']
    }
};

function getProductProfile() {
    const productType = document.getElementById('product_type')?.value || 'Intelligence Workspace';
    return PRODUCT_SECTION_PROFILE[productType] || PRODUCT_SECTION_PROFILE['Intelligence Workspace'];
}

function sectionRequirement(sectionId) {
    const profile = getProductProfile();
    if (profile.required.includes(sectionId)) return 'required';
    if (profile.recommended.includes(sectionId)) return 'recommended';
    return 'optional';
}

function showToast(message) {
    let toast = document.getElementById('fr-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'fr-toast';
        toast.className = 'fr-toast';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('is-visible');
    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => toast.classList.remove('is-visible'), 2800);
}

function toDatetimeLocal(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value).slice(0, 16);
    return date.toISOString().slice(0, 16);
}

function isSharingReviewOutdated() {
    const reviewedAt = document.getElementById('sharing_reviewed_at')?.value || '';
    const updatedAt = document.getElementById('updated_at')?.value || '';
    return !!reviewedAt && !!updatedAt && new Date(updatedAt) > new Date(reviewedAt);
}

function updateToolbarMeta() {
    const ref = document.getElementById('reference')?.value || '';
    const subject = document.getElementById('subject')?.value || '';
    const meta = document.getElementById('fr-toolbar-meta');
    if (meta) {
        meta.textContent = ref + (subject ? ' · ' + subject : '');
    }
}

function openHistoryDrawer() {
    document.getElementById('fr-drawer-overlay')?.classList.add('is-open');
    document.getElementById('fr-history-drawer')?.classList.add('is-open');
    renderSavedReportsList();
}

function closeHistoryDrawer() {
    document.getElementById('fr-drawer-overlay')?.classList.remove('is-open');
    document.getElementById('fr-history-drawer')?.classList.remove('is-open');
}

function showDraftBanner() {
    const banner = document.getElementById('fr-draft-banner');
    if (banner) banner.classList.add('is-visible');
}

function hideDraftBanner() {
    const banner = document.getElementById('fr-draft-banner');
    if (banner) banner.classList.remove('is-visible');
}

function loadDraft() {
    const draft = localStorage.getItem(DRAFT_STORAGE_KEY);
    if (!draft) return;
    try {
        populateFormData(JSON.parse(draft));
        hideDraftBanner();
        showToast('Draft restored');
        updateFieldStatus();
    } catch (e) {
        localStorage.removeItem(DRAFT_STORAGE_KEY);
    }
}

function dismissDraft() {
    localStorage.removeItem(DRAFT_STORAGE_KEY);
    hideDraftBanner();
}

function clearDraftStorage() {
    localStorage.removeItem(DRAFT_STORAGE_KEY);
    hideDraftBanner();
}

// ==================== WIZARD NAVIGATION ====================
function showBlock(blockNum) {
    blockNum = parseInt(blockNum, 10);
    currentBlock = blockNum;
    document.querySelectorAll('.flash-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.wizard-step').forEach(s => s.classList.remove('active'));
    const activeSection = document.getElementById('block-' + blockNum);
    if (activeSection) activeSection.classList.add('active');
    const activeStep = document.querySelector('.wizard-step[data-step="' + blockNum + '"]');
    if (activeStep) activeStep.classList.add('active');
    const prevBtn = document.getElementById('fr-prev-section');
    const nextBtn = document.getElementById('fr-next-section');
    if (prevBtn) prevBtn.disabled = blockNum <= 1;
    if (nextBtn) nextBtn.disabled = blockNum >= TOTAL_SECTIONS;
    syncSectionsStackHeight();
    updateProgressIndicator();
    updateToolbarMeta();
    scrollToActiveSection();
}

function syncSectionsStackHeight() {
    const stack = document.getElementById('fr-sections-stack');
    const active = document.querySelector('.fr-sections-stack > .flash-section.active');
    if (!stack || !active) return;
    stack.style.height = 'auto';
    stack.style.minHeight = '0';
    void stack.offsetHeight;
}

function scrollToActiveSection() {
    const target = document.querySelector('.fr-main') || document.getElementById('fr-sections-stack');
    if (!target) return;
    const top = target.getBoundingClientRect().top + window.scrollY - 96;
    window.scrollTo({ top: Math.max(0, top), behavior: 'smooth' });
}

function navigateSection(delta) {
    showBlock(Math.min(TOTAL_SECTIONS, Math.max(1, currentBlock + delta)));
}

document.querySelectorAll('.wizard-step').forEach(step => {
    step.addEventListener('click', function() {
        showBlock(this.dataset.step);
    });
});

document.getElementById('product_type')?.addEventListener('change', updateFieldStatus);

// ==================== BADGE SELECTION ====================
document.querySelectorAll('.badge-option').forEach(badge => {
    badge.addEventListener('click', function() {
        this.parentElement.querySelectorAll('.badge-option').forEach(b => b.classList.remove('selected'));
        this.classList.add('selected');
        updateFieldStatus();
    });
});

// ==================== ADD ROW FUNCTIONS ====================

// Add Takeaway Row
function addTakeaway() {
    const container = document.getElementById('takeaways-container');
    const row = document.createElement('div');
    row.className = 'takeaway-row';
    row.innerHTML = `
        <input type="text" class="takeaway-input" placeholder="Key point for decision makers">
        <select class="takeaway-likelihood"><option>N/A</option><option>Remote Chance</option><option>Realistic Possibility</option><option>Likely</option><option>Very Likely</option><option>Almost Certain</option></select>
        <select class="takeaway-confidence"><option>N/A</option><option>Low</option><option>Moderate</option><option>High</option></select>
        <input type="text" class="takeaway-evidence" placeholder="Evidence reference">
        <button type="button" class="btn-remove" onclick="this.parentElement.remove(); updateFieldStatus();" aria-label="Remove takeaway">×</button>
    `;
    container.appendChild(row);
    updateFieldStatus();
}

function addClaimRow(data = {}) {
    const tbody = document.querySelector('#claims-table tbody');
    if (!tbody) return;
    const row = document.createElement('tr');
    row.innerHTML = `
        <td><input type="text" value="${escHtml(data.claim_text || data.claim || '')}" placeholder="Analytic claim"></td>
        <td><select><option>OBSERVED</option><option>REPORTED</option><option>INFERRED</option><option>UNKNOWN</option></select></td>
        <td><input type="text" value="${escHtml(data.source_refs || '')}" placeholder="Source names, IDs, URLs"></td>
        <td><input type="text" value="${escHtml(data.evidence_refs || '')}" placeholder="Log, PCAP, sample, passage..."></td>
        <td><input type="text" value="${escHtml(data.rationale || data.unknown_reason || '')}" placeholder="Rationale or unknown reason"></td>
        <td><select><option>High</option><option>Moderate</option><option>Low</option><option>Unknown</option></select></td>
        <td><select><option>UNKNOWN</option><option>PRIMARY</option><option>SECONDARY</option><option>AGGREGATOR</option></select></td>
        <td><select><option>UNKNOWN</option><option>INDEPENDENT</option><option>DEPENDENT</option></select></td>
        <td><input type="text" value="${escHtml(data.depends_on_source || '')}" placeholder="Source ref"></td>
        <td><input type="text" value="${escHtml(data.conflicts_with || '')}" placeholder="CLAIM-002"></td>
        <td><input type="text" value="${escHtml(data.decision_impact || '')}" placeholder="HUNT, DETECTION, COLLECTION"></td>
        <td><input type="text" value="${escHtml(data.increase_confidence_if || '')}"></td>
        <td><input type="text" value="${escHtml(data.decrease_confidence_if || '')}"></td>
        <td><input type="text" value="${escHtml(data.related_gap_id || '')}" placeholder="GAP-001"></td>
        ${FR_REMOVE_CELL}
    `;
    const selects = row.querySelectorAll('select');
    if (data.claim_id) row.dataset.claimId = data.claim_id;
    selects[0].value = (data.analytical_status || data.status || 'REPORTED').toUpperCase();
    selects[1].value = data.confidence || 'Moderate';
    selects[2].value = (data.source_role || 'UNKNOWN').toUpperCase();
    selects[3].value = (data.source_independence || 'UNKNOWN').toUpperCase();
    tbody.appendChild(row);
    updateFieldStatus();
}

// Add Timeline Event Row
function addTimelineRow() {
    const tbody = document.querySelector('#timeline-table tbody');
    const row = document.createElement('tr');
    row.className = 'timeline-row';
    row.innerHTML = `
        <td><input type="datetime-local"></td>
        <td><input type="text" placeholder="Event description"></td>
        <td><select><option>Observed</option><option>Reported</option><option>Assessed</option></select></td>
        <td>
            <select>
                <option>Critical</option>
                <option>High</option>
                <option>Medium</option>
                <option>Low</option>
            </select>
        </td>
        <td><input type="text" placeholder="Source"></td>
        <td><input type="text" placeholder="Evidence reference"></td>
        ${FR_REMOVE_CELL}
    `;
    tbody.appendChild(row);
    updateFieldStatus();
}

// Add IOC Row
function addIocRow() {
    const tbody = document.querySelector('#iocs-table tbody');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>
            <select>
                <option>IP</option>
                <option>Domain</option>
                <option>URL</option>
                <option>Hash_MD5</option>
                <option>Hash_SHA1</option>
                <option>Hash_SHA256</option>
                <option>Email</option>
                <option>CIDR</option>
            </select>
        </td>
        <td><input type="text" class="fr-cell-mono" placeholder="Value"></td>
        <td><select><option>C2</option><option>Payload</option><option>Phishing</option><option>Redirector</option><option>Scanner</option><option>Staging</option><option>Malware Delivery</option><option>Victim</option><option>Unknown</option></select></td>
        <td><select><option>UNKNOWN</option><option>ATTACKER_CONTROLLED</option><option>VICTIM_INTERNAL</option><option>BENIGN_ENVIRONMENT</option></select></td>
        <td>
            <select>
                <option>RED</option>
                <option>AMBER</option>
                <option>GREEN</option>
            </select>
        </td>
        <td>
            <select>
                <option>High</option>
                <option>Medium</option>
                <option>Low</option>
            </select>
        </td>
        <td><select><option>Observed</option><option>Reported</option><option>Derived</option><option>Imported</option><option>Unknown</option></select></td>
        <td><input type="date"></td>
        <td><input type="date"></td>
        <td><input type="date"></td>
        <td><select><option>UNKNOWN</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></td>
        <td><select><option>UNKNOWN</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></td>
        <td><select><option>Active</option><option>Inactive</option><option>Historical</option><option>Expired</option><option>Unknown</option></select></td>
        <td><select><option>Hunt</option><option>Monitor</option><option>Detect</option><option>Block Candidate</option><option>Enrichment Only</option><option>Do Not Block</option></select></td>
        <td><input type="date"></td>
        <td><input type="text" placeholder="Context / relationship"></td>
        ${FR_REMOVE_CELL}
    `;
    tbody.appendChild(row);
    updateFieldStatus();
}

function addHuntLead(data = {}) {
    const container = document.getElementById('hunt-leads-container');
    const row = document.createElement('div');
    row.className = 'hunt-lead-row';
    const fields = [
        ['hypothesis', 'Hypothesis'], ['observable', 'What to Search'], ['data_source', 'Data Source'],
        ['time_window', 'Time Window'], ['expected_evidence', 'Expected Evidence'], ['pivot_hit', 'Pivot If Hit'], ['no_hit', 'Next Step If No Hit']
    ];
    fields.forEach(([key, label]) => {
        const group = document.createElement('div'); group.className = 'form-group';
        const caption = document.createElement('label'); caption.textContent = label;
        const input = document.createElement(key === 'hypothesis' || key === 'observable' || key === 'pivot_hit' || key === 'no_hit' ? 'textarea' : 'input');
        input.dataset.huntField = key;
        input.value = data[key] || '';
        input.addEventListener('input', updateFieldStatus);
        input.addEventListener('change', updateFieldStatus);
        group.append(caption, input);
        row.append(group);
    });
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'btn-remove'; remove.textContent = '×';
    remove.setAttribute('aria-label', 'Remove hunt lead'); remove.addEventListener('click', () => { row.remove(); updateFieldStatus(); }); row.append(remove);
    container.append(row); updateFieldStatus();
}

function addMitreDetailRow(data = {}) {
    const row=document.createElement('tr');
    row.innerHTML=`<td><input type="text" value="${escHtml(data.technique || '')}" placeholder="T1059"></td><td><input type="text" value="${escHtml(data.procedure || '')}"></td><td><select><option>Observed</option><option>Reported</option><option>Assessed</option></select></td><td><input type="text" value="${escHtml(data.evidence || '')}"></td><td><select><option>High</option><option>Moderate</option><option>Low</option></select></td>${FR_REMOVE_CELL}`;
    row.querySelectorAll('select')[0].value=data.status || 'Assessed'; row.querySelectorAll('select')[1].value=data.confidence || 'Moderate';
    document.querySelector('#mitre-details-table tbody').appendChild(row);
}

function addAttackSequenceRow(data = {}) {
    const row=document.createElement('tr');
    row.innerHTML=`<td><input type="number" min="1" value="${escHtml(data.step || '')}"></td><td><input type="datetime-local" value="${escHtml(data.date || '')}"></td><td><input type="text" value="${escHtml(data.technique || '')}"></td><td><input type="text" value="${escHtml(data.procedure || '')}"></td><td><input type="text" value="${escHtml(data.evidence || '')}"></td>${FR_REMOVE_CELL}`;
    document.querySelector('#attack-sequence-table tbody').appendChild(row);
}

function addGapRow(data = {}) {
    const row=document.createElement('tr');
    row.innerHTML=`<td><input type="text" value="${escHtml(data.gap_id || '')}" placeholder="GAP-001"></td><td><input type="text" value="${escHtml(data.question || data.gap || '')}" placeholder="Unresolved analytic question"></td><td><input type="text" value="${escHtml(data.requirement_id || data.linked_requirement || '')}" placeholder="IR / PIR reference"></td><td><input type="text" value="${escHtml(data.related_claim_id || '')}" placeholder="Claim ID"></td><td><input type="text" value="${escHtml(data.why_it_matters || '')}"></td><td><select><option>High</option><option>Medium</option><option>Low</option></select></td><td><input type="text" value="${escHtml(data.resolution || data.what_would_resolve_it || '')}"></td><td><input type="text" value="${escHtml(data.owner || '')}"></td><td><select><option>OPEN</option><option>RESOLVED</option></select></td><td><input type="text" value="${escHtml(data.resolution_summary || '')}"></td><td><input type="text" value="${escHtml(data.resolved_by_refs || '')}"></td><td><input type="datetime-local" value="${escHtml(data.resolved_at || '')}"></td>${FR_REMOVE_CELL}`;
    row.querySelectorAll('select')[0].value=data.priority || 'Medium'; row.querySelectorAll('select')[1].value=(data.status || 'OPEN').toUpperCase();
    document.querySelector('#gaps-table tbody').appendChild(row);
}

function addJournalRow(data = {}) {
    const tbody = document.querySelector('#investigation-journal-table tbody');
    if (!tbody) return;
    const row = document.createElement('tr');
    row.innerHTML = `<td><input type="text" value="${escHtml(data.entry_id || '')}" placeholder="JRN-001"></td><td><select><option>SEARCH</option><option>PIVOT</option><option>ENRICHMENT</option><option>VALIDATION</option><option>HUNT</option><option>REVIEW</option><option>NOTE</option></select></td><td><input type="datetime-local" value="${escHtml(data.performed_at || '')}"></td><td><input type="text" value="${escHtml(data.analyst || '')}"></td><td><input type="text" value="${escHtml(data.input_refs || '')}"></td><td><input type="text" value="${escHtml(data.operation || '')}"></td><td><input type="text" value="${escHtml(data.tool_or_source || '')}"></td><td><input type="text" value="${escHtml(data.query_or_method || '')}"></td><td><input type="text" value="${escHtml(data.scope || '')}"></td><td><input type="text" value="${escHtml(data.time_window || '')}"></td><td><select><option>HIT</option><option>NO_HIT</option><option>INCONCLUSIVE</option><option>NO_DATA</option><option>ERROR</option></select></td><td><input type="text" value="${escHtml(data.result_summary || '')}"></td><td><input type="text" value="${escHtml(data.coverage || '')}"></td><td><input type="text" value="${escHtml(data.limitations || '')}"></td><td><input type="text" value="${escHtml(data.output_refs || '')}"></td><td><input type="text" value="${escHtml(data.next_step || '')}"></td>${FR_REMOVE_CELL}`;
    const selects = row.querySelectorAll('select');
    selects[0].value = (data.entry_type || 'SEARCH').toUpperCase();
    selects[1].value = (data.result_type || 'INCONCLUSIVE').toUpperCase();
    tbody.appendChild(row);
    updateFieldStatus();
}

// Add Detection Rule
function addDetectionRule() {
    const container = document.querySelector('#block-8 .form-group');
    const ruleDiv = document.createElement('div');
    ruleDiv.className = 'rule-container';
    ruleDiv.innerHTML = `
        <div class="rule-container-header">
            <select class="rule-type">
                <option value="SIGMA">SIGMA</option>
                <option value="YARA">YARA</option>
                <option value="KQL">KQL</option>
                <option value="SPL">SPL</option>
                <option value="Snort">Snort</option>
                <option value="HUNT_LOGIC">HUNT_LOGIC</option>
                <option value="NOT_APPLICABLE">NOT_APPLICABLE</option>
            </select>
            <button type="button" class="btn-remove" onclick="this.closest('.rule-container').remove(); updateFieldStatus();" aria-label="Remove rule">×</button>
        </div>
        <textarea placeholder="Enter detection rule here..."></textarea>
    `;
    container.insertBefore(ruleDiv, container.lastElementChild);
    updateFieldStatus();
}

function addJournalQuickEntry(operation) {
    const now = new Date();
    const localIso = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    addJournalRow({
        entry_type: 'SEARCH',
        performed_at: localIso,
        operation: operation,
        result_type: 'INCONCLUSIVE'
    });
}

async function checkSigmaCoverage() {
    const resultEl = document.getElementById('sigma-coverage-results');
    if (!resultEl) return;
    const techniqueIds = Array.from(document.querySelectorAll('#ttps-container .ttp-chip'))
        .map(chip => (chip.dataset.id || '').trim().toUpperCase())
        .filter(Boolean);
    const rulesText = Array.from(document.querySelectorAll('#block-8 .rule-container textarea'))
        .map(textarea => textarea.value || '')
        .join('\n---\n');

    if (!techniqueIds.length) {
        resultEl.textContent = 'Add MITRE ATT&CK TTPs before checking Sigma ATT&CK mapping.';
        return;
    }
    resultEl.textContent = 'Checking Sigma ATT&CK mapping...';
    try {
        const response = await fetch('/api/flash-report/sigma-coverage', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({technique_ids: techniqueIds, rules_text: rulesText})
        });
        const data = await response.json();
        if (!response.ok || !data.success) {
            resultEl.textContent = data.error || 'Unable to check Sigma ATT&CK mapping.';
            return;
        }
        const rows = data.coverage || [];
        resultEl.innerHTML = `
            <div style="margin-bottom: 8px;">${escHtml(data.scope_note || 'Mapping is based on explicit ATT&CK tags in Sigma rules.')}</div>
            <div class="fr-table-scroll" style="margin-top: 8px;">
                <table class="data-table">
                    <thead><tr><th>Technique</th><th>Status</th><th>Reason</th></tr></thead>
                    <tbody>
                        ${rows.map(row => `<tr><td>${escHtml(row.technique_id)}</td><td>${escHtml(row.status)}</td><td>${escHtml(row.reason)}</td></tr>`).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (error) {
        resultEl.textContent = 'Error: ' + error.message;
    }
}

// Add Recommendation Row
function addRecommendationRow() {
    const tbody = document.querySelector('#recommendations-table tbody');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>
            <select>
                <option value="Immediate">Immediate</option>
                <option value="Short">Short term</option>
                <option value="Medium">Medium term</option>
            </select>
        </td>
        <td><input type="text" placeholder="Action description"></td>
        <td>
            <select>
                <option>Patch</option>
                <option>Block</option>
                <option>Monitor</option>
                <option>Isolate</option>
                <option>Hunt</option>
                <option>Notify</option>
                <option>Escalate</option>
                <option>Remediate</option>
                <option>Investigate</option>
                <option>Detection</option>
            </select>
        </td>
        <td><input type="text" placeholder="Team/Person"></td>
        <td><input type="date"></td>
        <td>
            <select>
                <option>Todo</option>
                <option>In Progress</option>
                <option>Blocked</option>
                <option>Done</option>
                <option>Cancelled</option>
            </select>
        </td>
        <td><select><option>Do Now</option><option>Do If Confirmed</option><option>Monitor</option><option>Optional</option></select></td>
        <td><input type="text" placeholder="CLAIM-001"></td>
        <td><input type="text" placeholder="GAP-001"></td>
        <td><input type="text" placeholder="Expected outcome"></td>
        <td><input type="text" placeholder="Evidence of completion"></td>
        ${FR_REMOVE_CELL}
    `;
    tbody.appendChild(row);
    updateFieldStatus();
}

// Add Source Row
function addSourceRow() {
    const tbody = document.querySelector('#sources-table tbody');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td><input type="text" placeholder="Source name"></td>
        <td>
            <select>
                <option>RED</option>
                <option>AMBER</option>
                <option>GREEN</option>
                <option>CLEAR</option>
            </select>
        </td>
        <td>
            <select>
                <option>A</option>
                <option>B</option>
                <option>C</option>
                <option>D</option>
                <option>E</option>
            </select>
        </td>
        <td><select><option>UNKNOWN</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></td>
        <td><input type="date"></td>
        <td><input type="text" list="cti_urls_list" placeholder="https://..."></td>
        <td>
            <select>
                <option>INTERNAL_TELEMETRY</option>
                <option>HUMAN_REPORT</option>
                <option>INCIDENT_RECORD</option>
                <option>ADVISORY</option>
                <option>VENDOR_REPORT</option>
                <option>OSINT</option>
                <option>OTHER</option>
            </select>
        </td>
        <td><select><option>Primary</option><option>Secondary</option></select></td>
        <td><select><option>Direct</option><option>Derived</option><option>Cited</option></select></td>
        ${FR_REMOVE_CELL}
    `;
    tbody.appendChild(row);
    updateFieldStatus();
}

function addEvidenceRow(data = {}) {
    const tbody = document.querySelector('#evidence-table tbody');
    if (!tbody) return;
    const row = document.createElement('tr');
    row.innerHTML = `
        <td><input type="text" value="${escHtml(data.evidence_id || '')}" placeholder="EVID-001"></td>
        <td><input type="text" value="${escHtml(data.type || '')}" placeholder="Identity Log Event"></td>
        <td><input type="text" value="${escHtml(data.description || '')}" placeholder="What this evidence is"></td>
        <td><input type="text" value="${escHtml(data.source_ref || '')}" placeholder="SRC-001"></td>
        <td><input type="datetime-local" value="${escHtml(data.observed_at || '')}"></td>
        <td><input type="text" value="${escHtml(data.location || '')}" placeholder="Event ID, file path, ticket..."></td>
        <td><input type="text" value="${escHtml(data.collected_by || '')}" placeholder="SOC, CTI, IR..."></td>
        <td><input type="text" value="${escHtml(data.integrity || '')}" placeholder="Hash or integrity note"></td>
        <td><input type="text" value="${escHtml(data.notes || '')}"></td>
        ${FR_REMOVE_CELL}
    `;
    tbody.appendChild(row);
    updateFieldStatus();
}

function addDataAvailabilityRow(data = {}) {
    const tbody = document.querySelector('#data-availability-table tbody');
    if (!tbody) return;
    const row = document.createElement('tr');
    row.innerHTML = `<td><input type="text" value="${escHtml(data.data_source || '')}" placeholder="EDR Process, DNS, Proxy..."></td><td><select><option>YES</option><option>NO</option><option>UNKNOWN</option></select></td><td><select><option>UNKNOWN</option><option>YES</option><option>NO</option><option>PARTIAL</option></select></td><td><input type="text" value="${escHtml(data.retention || '')}" placeholder="30d"></td><td><input type="text" value="${escHtml(data.coverage || '')}" placeholder="92% / scoped notes"></td><td><input type="text" value="${escHtml(data.limitation || '')}" placeholder="Known limitation"></td><td class="fr-table-actions"><button type="button" class="btn-mini" onclick="createGapFromDataAvailability(this)">Gap</button><button type="button" class="btn-mini" onclick="recordLimitationFromDataAvailability(this)">Limit</button><button type="button" class="btn-remove" onclick="this.closest('tr').remove(); updateFieldStatus();" aria-label="Remove row">×</button></td>`;
    const selects = row.querySelectorAll('select');
    selects[0].value = data.needed || 'YES';
    selects[1].value = data.available || 'UNKNOWN';
    tbody.appendChild(row);
    updateFieldStatus();
}

function getDataAvailabilityRowData(button) {
    const row = button.closest('tr');
    const inputs = row?.querySelectorAll('input, select') || [];
    return {
        data_source: inputs[0]?.value || '',
        needed: inputs[1]?.value || 'YES',
        available: inputs[2]?.value || 'UNKNOWN',
        retention: inputs[3]?.value || '',
        coverage: inputs[4]?.value || '',
        limitation: inputs[5]?.value || ''
    };
}

function createGapFromDataAvailability(button) {
    const rowData = getDataAvailabilityRowData(button);
    if (!rowData.data_source.trim()) {
        showToast('Enter a data source first');
        return;
    }
    addGapRow({
        question: `What is the impact of unavailable or limited ${rowData.data_source} data on this requirement?`,
        why_it_matters: rowData.limitation || `Availability is ${rowData.available}.`,
        resolution: `Obtain ${rowData.data_source} data or document an accepted limitation.`,
        priority: rowData.available === 'NO' ? 'High' : 'Medium',
        status: 'OPEN'
    });
    showBlock(10);
    showToast('Intelligence gap created from data availability');
}

function recordLimitationFromDataAvailability(button) {
    const rowData = getDataAvailabilityRowData(button);
    if (!rowData.data_source.trim()) {
        showToast('Enter a data source first');
        return;
    }
    const target = document.getElementById('known_unknowns');
    if (!target) return;
    const line = `${rowData.data_source}: ${rowData.available}${rowData.coverage ? `, coverage ${rowData.coverage}` : ''}${rowData.retention ? `, retention ${rowData.retention}` : ''}${rowData.limitation ? ` - ${rowData.limitation}` : ''}`;
    target.value = [target.value.trim(), line].filter(Boolean).join('\n');
    showBlock(10);
    updateFieldStatus();
    showToast('Collection limitation recorded');
}

// Add Recipient Row
function addRecipientRow() {
    const tbody = document.querySelector('#recipients-table tbody');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td><input type="text" placeholder="Full name"></td>
        <td><input type="text" placeholder="CISO, SOC Lead..."></td>
        <td><input type="text" placeholder="Organization"></td>
        <td><input type="email" placeholder="email@org.com"></td>
        ${FR_REMOVE_CELL}
    `;
    tbody.appendChild(row);
    updateFieldStatus();
}

// ==================== REPORT MANAGEMENT SYSTEM ====================

const REPORTS_STORAGE_KEY = 'flint_saved_reports';
let currentReportId = null;

const SAMPLE_INTELLIGENCE_WORKSPACE = {
    reference: 'FLINT-2026-027-SAMPLE',
    created_at: '2026-09-26T08:35',
    author: 'CTI Analyst 01',
    tlp: 'AMBER',
    pap: 'AMBER',
    priority: 'High',
    status: 'Review',
    product_type: 'Incident Intelligence Support',
    pir: 'N/A',
    purpose: 'Determine whether a credential-phishing activity observed against an internal Microsoft 365 user resulted in account compromise, whether additional users may have been targeted, and which defensive actions are required. SAMPLE DATA ONLY.',
    intelligence_requirement: 'Did the phishing activity observed on 24 September 2026 result in unauthorized access to the organization, and does available evidence indicate broader targeting of additional employees?',
    requester: 'SOC / Incident Response',
    intended_consumers: 'SOC, CSIRT, Identity & Access Management, Email Security, CTI Lead',
    decision_requirement: 'Determine whether the affected account must be treated as compromised, whether organization-wide hunting is required, and whether the observed infrastructure should be blocked.',
    decision_deadline: '2026-09-26T17:00',
    deadline_reason: 'SOC needs a decision before the end-of-day containment review.',
    scope: 'Microsoft 365 tenant, affected Finance user, corporate Windows endpoints, email telemetry, identity telemetry and network telemetry covering 24 August-26 September 2026.',
    subject: '[SAMPLE - PHISHING / ACCOUNT TAKEOVER] Microsoft 365 credential-phishing activity against Finance user',
    incident_type: 'Phishing / Account Takeover',
    investigation_status: 'Under Investigation',
    cves: 'N/A - no vulnerability exploitation identified.',
    threat_actor: 'Unattributed activity - internally tracked as CLUSTER-2026-09-PHISH-01',
    attribution_basis: 'Unattributed',
    affected_entities: 'One Finance employee and the associated Microsoft 365 account are confirmed in scope. No additional affected accounts have been identified in the telemetry reviewed so far.',
    threat_nature: 'The user received a file-sharing themed phishing email containing a link to a credential-harvesting page. Approximately two minutes after the user accessed the link, the Microsoft 365 account recorded a successful authentication from previously unseen external infrastructure. A mailbox forwarding rule was created shortly afterward.',
    impact_confidentiality: 'High',
    impact_integrity: 'Medium',
    impact_availability: 'Low',
    observed_impact: 'Unauthorized Microsoft 365 authentication and creation of an unauthorized mailbox forwarding rule were observed. No confirmed data exfiltration or malicious email sent from the compromised account has been identified as of the assessment time.',
    urgency_action: 'Immediate containment completed. Organization-wide retrospective search should be completed within 24 hours.',
    initial_signal: 'Email Security escalated a user-reported file-sharing message after the recipient reported an unexpected Microsoft 365 reauthentication prompt.',
    why_it_matters: 'The temporal correlation between the phishing interaction, anomalous authentication and subsequent mailbox configuration change indicates that the incident may have progressed beyond phishing delivery into account compromise.',
    required_action: 'Immediate containment included session revocation, credential reset, mailbox-rule removal and infrastructure blocking. Remaining work focuses on IAM session analysis and detection engineering.',
    key_judgements: [
        {judgement: 'The unauthorized Microsoft 365 authentication was related to the phishing interaction.', likelihood: 'Very Likely', confidence: 'High', evidence: 'CLAIM-001, CLAIM-002, CLAIM-003'},
        {judgement: 'The available evidence supports credential/account theft as the primary working hypothesis, but does not establish whether the attacker obtained the password directly, stole a session/token, or possessed the credentials beforehand.', likelihood: 'N/A', confidence: 'High', evidence: 'CLAIM-004, CLAIM-005'},
        {judgement: 'No evidence currently supports attribution to a named threat actor or established campaign.', likelihood: 'N/A', confidence: 'High', evidence: 'CLAIM-006'}
    ],
    data_availability: [
        {data_source: 'M365 sign-in logs', needed: 'YES', available: 'YES', retention: '90 days', coverage: '~100% tenant', limitation: 'None identified'},
        {data_source: 'Unified Audit Log', needed: 'YES', available: 'YES', retention: '90 days', coverage: 'Tenant-wide', limitation: 'Ingestion delay possible'},
        {data_source: 'Email message trace', needed: 'YES', available: 'YES', retention: '90 days', coverage: 'Tenant-wide', limitation: 'Body content not always retained'},
        {data_source: 'Secure Web Gateway', needed: 'YES', available: 'YES', retention: '14 days', coverage: '~87% endpoints', limitation: 'Roaming/direct SaaS traffic partially absent'},
        {data_source: 'EDR process telemetry', needed: 'YES', available: 'YES', retention: '30 days', coverage: '~94% Windows estate', limitation: 'Offline laptops absent during periods'},
        {data_source: 'DNS logs', needed: 'YES', available: 'YES', retention: '30 days', coverage: 'Corporate resolvers', limitation: 'Roaming devices may bypass resolver'},
        {data_source: 'Browser form submission telemetry', needed: 'YES', available: 'NO', retention: 'N/A', coverage: '0%', limitation: 'Not collected'},
        {data_source: 'Asset inventory', needed: 'YES', available: 'YES', retention: 'Current +24h', coverage: 'Corporate managed assets', limitation: 'SaaS users not represented as assets'}
    ],
    threat_history: 'No related activity was identified in ODYSAFE Memory for the observed phishing domain or infrastructure before 24 September 2026.',
    affected_scope: 'One Finance employee and one Microsoft 365 account confirmed. Broader targeting remains under investigation.',
    first_observed: '2026-09-24T07:41',
    patch_date: '',
    timeline: [
        {date: '2026-09-24T07:41', event: 'Phishing message delivered', status: 'Observed', significance: 'High', source: 'SRC-001', evidence: 'EVID-001'},
        {date: '2026-09-24T07:46', event: 'User accesses phishing URL', status: 'Observed', significance: 'High', source: 'SRC-002', evidence: 'EVID-002'},
        {date: '2026-09-24T07:48', event: 'Successful M365 sign-in from 203.0.113.42', status: 'Observed', significance: 'Critical', source: 'SRC-003', evidence: 'EVID-003'},
        {date: '2026-09-24T07:52', event: 'New mailbox forwarding rule created', status: 'Observed', significance: 'Critical', source: 'SRC-004', evidence: 'EVID-004'},
        {date: '2026-09-24T08:16', event: 'SOC revokes sessions', status: 'Observed', significance: 'High', source: 'SRC-006', evidence: 'EVID-006'}
    ],
    ttps: [
        {id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access'},
        {id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion / Persistence / Privilege Escalation / Initial Access'},
        {id: 'T1114.003', name: 'Email Forwarding Rule', tactic: 'Collection'}
    ],
    mitre_details: [
        {technique: 'T1566.002', procedure: 'A file-sharing themed email directed the victim to an external credential-phishing URL.', status: 'Observed', evidence: 'EVID-001, EVID-002', confidence: 'High'},
        {technique: 'T1078', procedure: "The victim's Microsoft 365 account was used to authenticate successfully from external infrastructure not previously associated with the account.", status: 'Observed', evidence: 'EVID-003', confidence: 'High'},
        {technique: 'T1114.003', procedure: 'A mailbox rule forwarding selected incoming messages to an external mailbox was created after the suspicious authentication.', status: 'Observed', evidence: 'EVID-004', confidence: 'High'}
    ],
    diamond_adversary: 'Unknown. No actor-level attribution established.',
    diamond_infrastructure: 'secure-share-login.example; 203.0.113.42',
    diamond_capability: 'Credential-phishing infrastructure and subsequent use of compromised cloud credentials.',
    diamond_victim: 'Finance employee / Microsoft 365 account / ACME France fictitious environment.',
    attack_vector: 'Spearphishing link leading to a Microsoft 365-themed credential-harvesting page.',
    malware_family: 'N/A - no malware execution observed.',
    persistence: 'No endpoint persistence identified. An unauthorized mailbox forwarding rule was observed.',
    c2_infrastructure: 'N/A - no malware C2 identified.',
    anchor: 'The strongest discriminator is the short sequence linking phishing URL access, first-seen external authentication and unauthorized mailbox configuration change.',
    working_hypothesis: 'The employee submitted authentication material to the phishing page, enabling unauthorized Microsoft 365 access.',
    evidence_for: 'Phishing email delivered; victim clicked external URL; anomalous successful authentication occurred two minutes later; unauthorized forwarding rule followed shortly afterward; infrastructure had not previously authenticated to the account.',
    evidence_against: 'No direct evidence shows the victim entering a password into the phishing page.',
    alternative_explanation: 'The account credentials or session material may have been compromised before the phishing message and the temporal correlation may be coincidental.',
    next_best_pivot: 'Review authentication method, MFA details, session identifiers and browser telemetry to determine whether password theft or token/session theft better explains the successful authentication.',
    attack_sequence: [
        {step: '1', date: '2026-09-24T07:41', technique: 'T1566.002', procedure: 'Phishing link delivered', evidence: 'EVID-001'},
        {step: '2', date: '2026-09-24T07:46', technique: 'T1566.002', procedure: 'Victim accesses lure', evidence: 'EVID-002'},
        {step: '3', date: '2026-09-24T07:48', technique: 'T1078', procedure: 'Account used externally', evidence: 'EVID-003'},
        {step: '4', date: '2026-09-24T07:52', technique: 'T1114.003', procedure: 'Mail forwarding rule created', evidence: 'EVID-004'}
    ],
    iocs: [
        {type: 'Domain', value: 'secure-share-login.example', role: 'Phishing', artifact_context: 'ATTACKER_CONTROLLED', tlp: 'AMBER', confidence: 'High', origin: 'Email / Proxy', first_seen: '2026-09-24', last_seen: '2026-09-24', last_validated: '2026-09-26', discriminative_value: 'HIGH', false_positive_risk: 'LOW', operational_status: 'Active', recommended_use: 'Block Candidate', review_date: '2026-10-03', context: 'SAMPLE ONLY - phishing domain reserved under .example'},
        {type: 'URL', value: 'hxxps://secure-share-login[.]example/m365', role: 'Phishing', artifact_context: 'ATTACKER_CONTROLLED', tlp: 'AMBER', confidence: 'High', origin: 'Email', first_seen: '2026-09-24', last_seen: '2026-09-24', last_validated: '2026-09-26', discriminative_value: 'HIGH', false_positive_risk: 'LOW', operational_status: 'Active', recommended_use: 'Hunt', review_date: '2026-10-03', context: 'SAMPLE ONLY - defanged lure URL'},
        {type: 'IP', value: '203.0.113.42', role: 'Unknown', artifact_context: 'ATTACKER_CONTROLLED', tlp: 'AMBER', confidence: 'High', origin: 'Identity Logs', first_seen: '2026-09-24', last_seen: '2026-09-24', last_validated: '2026-09-26', discriminative_value: 'MEDIUM', false_positive_risk: 'MEDIUM', operational_status: 'Active', recommended_use: 'Hunt', review_date: '2026-10-03', context: 'SAMPLE ONLY - TEST-NET-3 reserved address used as authentication source'},
        {type: 'Email', value: 'notifications@secure-share-login.example', role: 'Phishing', artifact_context: 'ATTACKER_CONTROLLED', tlp: 'AMBER', confidence: 'High', origin: 'Email Gateway', first_seen: '2026-09-24', last_seen: '2026-09-24', last_validated: '2026-09-26', discriminative_value: 'HIGH', false_positive_risk: 'LOW', operational_status: 'Active', recommended_use: 'Block Candidate', review_date: '2026-10-03', context: 'SAMPLE ONLY - sender value in reserved .example domain'},
        {type: 'IP', value: '10.24.18.17', role: 'Victim', artifact_context: 'VICTIM_INTERNAL', tlp: 'AMBER', confidence: 'High', origin: 'EDR', first_seen: '2026-09-24', last_seen: '2026-09-24', last_validated: '2026-09-26', discriminative_value: 'LOW', false_positive_risk: 'HIGH', operational_status: 'Active', recommended_use: 'Do Not Block', review_date: '2026-10-03', context: 'SAMPLE ONLY - victim workstation context, not an attacker IOC'}
    ],
    detection_rules: [
        {type: 'HUNT_LOGIC', content: 'Identity compromise hunt logic: search successful sign-ins involving the observed source IP, previously unseen source networks for the affected user, unusual user-agent combinations, and authentication immediately followed by mailbox configuration changes.'}
    ],
    detection_validation_status: 'Draft',
    detection_telemetry: 'Microsoft 365 sign-in logs, Unified Audit Log, email message trace, secure web gateway and EDR browser/process telemetry.',
    detection_false_positives: 'Legitimate VPN or travel may produce first-seen IP addresses. Administrators and users may legitimately create mailbox forwarding rules. Correlate each signal with account history and surrounding events.',
    hunt_leads: [
        {hypothesis: 'Additional recipients received the same lure.', observable: 'Messages containing secure-share-login.example', data_source: 'Email message trace', time_window: '30 days', expected_evidence: 'Recipient list and delivery events', pivot_hit: 'Review clicks and authentications', no_hit: 'Document current scope limitation'},
        {hypothesis: 'The same infrastructure authenticated to other accounts.', observable: '203.0.113.42', data_source: 'M365 sign-in logs', time_window: '90 days', expected_evidence: 'Additional account sign-ins', pivot_hit: 'Contain affected accounts', no_hit: 'Record NO_HIT with tenant-wide coverage'},
        {hypothesis: 'Mailbox forwarding rules were created after anomalous authentication.', observable: 'Forwarding rule creation after first-seen external sign-in', data_source: 'Unified Audit Log', time_window: '30 days', expected_evidence: 'Mailbox rule changes', pivot_hit: 'Investigate affected mailboxes', no_hit: 'Retain as detection engineering lead'}
    ],
    hunt_result: 'One affected account identified. No additional matches were identified in the currently available telemetry. See investigation entries INV-002 through INV-005 for scope and limitations.',
    hunt_interpretation: 'The negative hunt results reduce concern for broader compromise within the reviewed telemetry, but do not prove absence outside the stated scope.',
    hunt_follow_up: 'Complete IAM review of authentication/session details and improve proxy retention.',
    analytic_claims: [
        {claim_id: 'CLAIM-001', claim_text: 'The targeted employee accessed the phishing URL at 07:46 UTC on 24 September 2026.', analytical_status: 'OBSERVED', source_refs: 'SRC-001, SRC-002', evidence_refs: 'EVID-001, EVID-002', confidence: 'High', source_role: 'PRIMARY', source_independence: 'INDEPENDENT', decision_impact: 'INCIDENT_RESPONSE, HUNT'},
        {claim_id: 'CLAIM-002', claim_text: 'The affected Microsoft 365 account successfully authenticated from 203.0.113.42 approximately two minutes after the phishing URL was accessed.', analytical_status: 'OBSERVED', source_refs: 'SRC-003', evidence_refs: 'EVID-003', confidence: 'High', source_role: 'PRIMARY', source_independence: 'INDEPENDENT', decision_impact: 'INCIDENT_RESPONSE'},
        {claim_id: 'CLAIM-003', claim_text: 'An unauthorized mailbox forwarding rule was created shortly after the anomalous authentication.', analytical_status: 'OBSERVED', source_refs: 'SRC-004', evidence_refs: 'EVID-004', confidence: 'High', source_role: 'PRIMARY', source_independence: 'INDEPENDENT'},
        {claim_id: 'CLAIM-004', claim_text: 'The account compromise likely resulted from interaction with the phishing lure.', analytical_status: 'INFERRED', evidence_refs: 'EVID-001, EVID-002, EVID-003, EVID-004', rationale: 'The phishing interaction, first anomalous successful authentication and mailbox rule creation occurred within approximately ten minutes. No previous authentication from the observed infrastructure was identified in the available 90-day identity history.', confidence: 'High', increase_confidence_if: 'Browser or phishing-kit evidence confirms credential submission by the victim.', decrease_confidence_if: 'Evidence is identified showing the account was compromised before the phishing message was delivered.', related_gap_id: 'GAP-001'},
        {claim_id: 'CLAIM-005', claim_text: 'The exact authentication material obtained by the attacker is unknown.', analytical_status: 'UNKNOWN', unknown_reason: 'Available logs establish unauthorized account use but do not establish whether the attacker captured the password, a session token, or another authentication artifact.', confidence: 'N/A', source_role: 'N/A', source_independence: 'N/A', related_gap_id: 'GAP-001'},
        {claim_id: 'CLAIM-006', claim_text: 'The responsible threat actor cannot currently be determined.', analytical_status: 'UNKNOWN', unknown_reason: 'Infrastructure and observed behaviors are not sufficiently distinctive to support actor attribution.', confidence: 'N/A', source_role: 'N/A', source_independence: 'N/A', related_gap_id: 'GAP-003'},
        {claim_id: 'CLAIM-007', claim_text: 'No matching activity was identified for additional employees in the available email and identity telemetry reviewed to date.', analytical_status: 'OBSERVED', evidence_refs: 'EVID-007, EVID-008', rationale: 'Search was limited by 14-day proxy retention and incomplete roaming-endpoint visibility.', confidence: 'Medium'}
    ],
    gaps: [
        {gap_id: 'GAP-001', question: 'What authentication material did the attacker obtain?', requirement_id: 'IR-2026-014', related_claim_id: 'CLAIM-005', why_it_matters: 'Determines whether password reset alone is sufficient or whether token/session theft must also be considered.', priority: 'High', resolution: 'Browser/session telemetry, phishing-kit capture, authentication details or identity-provider token evidence.', owner: 'IR / IAM', status: 'OPEN'},
        {gap_id: 'GAP-002', question: 'Were additional employees targeted or compromised by the same infrastructure?', requirement_id: 'IR-2026-014', why_it_matters: 'Determines whether this is an isolated account compromise or a broader campaign affecting the organization.', priority: 'High', resolution: 'Search available message trace, identity, proxy and EDR telemetry.', owner: 'SOC', status: 'RESOLVED', resolution_summary: 'Searches across available message trace, identity, proxy and EDR telemetry identified no additional affected users.', resolved_by_refs: 'INV-002, INV-003, INV-005', resolved_at: '2026-09-26T13:20'},
        {gap_id: 'GAP-003', question: 'Can this activity be reliably linked to a known actor or campaign?', requirement_id: 'IR-2026-014', related_claim_id: 'CLAIM-006', why_it_matters: 'Attribution could support broader campaign tracking but is not required for immediate containment.', priority: 'Low', resolution: 'Distinctive infrastructure, tooling, lure reuse, or corroborated reporting.', owner: 'CTI', status: 'OPEN'},
        {gap_id: 'GAP-004', question: 'Was MFA successfully completed, bypassed, or absent during the malicious authentication?', requirement_id: 'IR-2026-014', why_it_matters: 'Determines whether identity controls require adjustment.', priority: 'High', resolution: 'Authentication details and IAM session review that explicitly answers MFA completion, bypass or absence.', owner: 'IAM', status: 'OPEN', resolution_summary: 'Authentication records indicate the session satisfied the configured authentication requirement, but available telemetry does not fully answer whether MFA was completed, bypassed, or absent.'}
    ],
    investigation_journal: [
        {entry_id: 'INV-001', entry_type: 'REVIEW', performed_at: '2026-09-26T08:50', analyst: 'CTI Analyst 01', input_refs: 'SRC-001', operation: 'Review phishing message headers and URL.', tool_or_source: 'Email Security', result_type: 'HIT', result_summary: 'Message delivered to one Finance employee contained the observed phishing URL.'},
        {entry_id: 'INV-002', entry_type: 'SEARCH', performed_at: '2026-09-26T09:10', analyst: 'CTI Analyst 01', input_refs: '203.0.113.42', operation: 'Search Microsoft 365 sign-ins for source IP.', tool_or_source: 'M365 sign-in logs', scope: 'Microsoft 365 tenant', time_window: '90 days', result_type: 'HIT', result_summary: 'One successful authentication involving the affected account. No other tenant accounts matched.', coverage: 'Tenant-wide identity logs.', limitations: 'None identified for the requested time window.'},
        {entry_id: 'INV-003', entry_type: 'HUNT', performed_at: '2026-09-26T09:45', analyst: 'CTI Analyst 01', input_refs: 'secure-share-login.example', operation: 'Search web telemetry for additional access.', tool_or_source: 'Secure Web Gateway', query_or_method: 'Domain query for secure-share-login.example and URL variants in proxy logs.', scope: 'Corporate endpoints with proxy visibility', time_window: '14 days', result_type: 'NO_HIT', result_summary: 'No additional users were observed accessing the domain.', coverage: '87% estimated endpoint web visibility.', limitations: 'Roaming and direct SaaS traffic not fully captured.'},
        {entry_id: 'INV-004', entry_type: 'VALIDATION', performed_at: '2026-09-26T10:20', analyst: 'CTI Analyst 01', operation: 'Determine whether victim submitted credentials to phishing page.', tool_or_source: 'Browser telemetry', result_type: 'NO_DATA', result_summary: 'Browser form submission telemetry is not collected.', limitations: 'No direct browser form submission record is available.', next_step: 'Maintain credential-theft hypothesis but keep exact credential acquisition mechanism unresolved.'},
        {entry_id: 'INV-005', entry_type: 'HUNT', performed_at: '2026-09-26T11:05', analyst: 'CTI Analyst 01', operation: 'Search email tenant for sender/domain.', tool_or_source: 'Email message trace', query_or_method: 'Message trace query for sender notifications@secure-share-login.example and domain secure-share-login.example.', scope: 'All mailboxes', time_window: '30 days', result_type: 'NO_HIT', result_summary: 'No additional messages matching the sender/domain were found.', coverage: 'Complete message-trace coverage for requested window.', limitations: 'Body content not always retained.'}
    ],
    handoff: {
        current_situation: 'One Microsoft 365 account was accessed shortly after the user interacted with a phishing lure. The account has been contained. Broader hunt has not identified additional affected users.',
        established_assessments: 'CLAIM-001, CLAIM-002, CLAIM-003, CLAIM-007',
        outstanding_questions: 'GAP-001, GAP-003',
        next_step: 'Review authentication/session details with IAM to determine whether token/session theft remains plausible.',
        blocked_by: 'Browser credential submission telemetry unavailable.',
        owner: 'CTI / IR',
        warning: 'Absence of additional hits is constrained by proxy and endpoint visibility.'
    },
    overall_confidence: 'Highly Likely',
    overall_analytic_confidence: 'High',
    confidence_rationale: 'The assessment is supported by multiple independent internal telemetry sources: message trace, web telemetry, identity logs and Microsoft 365 audit events. The main unresolved element is the exact credential or session theft mechanism.',
    key_assumptions: "Timestamps across telemetry sources are sufficiently synchronized; the victim's normal authentication behavior is accurately represented by the available 90-day history; no earlier compromise outside the observed telemetry window explains the authentication.",
    biases: 'The current evidence does not directly demonstrate credential submission to the phishing page. A prior compromise or stolen session obtained through another mechanism remains possible.',
    section_confidence: 'Phishing delivery: High; User interaction: High; Unauthorized account use: High; Exact credential theft mechanism: Low; Broader organizational scope: Medium; Attribution: Low; Observed impact: High.',
    internal_relevance: {
        technology_relevance: 'YES',
        affected_version_status: 'NOT_APPLICABLE',
        internet_exposure: 'NOT_APPLICABLE',
        sector_relevance: 'NOT_ASSESSED',
        geographic_relevance: 'NOT_ASSESSED',
        supplier_relevance: 'NOT_ASSESSED',
        internal_observation: 'YES',
        overall_relevance: 'HIGH',
        relevance_decision: 'IMMEDIATE_ACTION',
        rationale: 'The activity directly affected an internal production account and therefore has high organizational relevance independent of actor attribution or general threat severity.',
        assessed_by: 'CTI Analyst 01',
        assessed_at: '2026-09-26T14:30'
    },
    recommendations: [
        {priority: 'Immediate', action: 'Revoke active sessions and reset credentials', type: 'Isolate', owner: 'IAM', due_date: '2026-09-26', status: 'Done', trigger: 'Do Now', linked_claim: 'CLAIM-002', expected_outcome: 'Prevent continued account use', completion_evidence: 'IR-TICKET-2026-441 - session revocation completed 08:16 UTC.'},
        {priority: 'Immediate', action: 'Remove unauthorized forwarding rule', type: 'Remediate', owner: 'M365 Admin', due_date: '2026-09-26', status: 'Done', trigger: 'Do Now', linked_claim: 'CLAIM-003', expected_outcome: 'Stop unauthorized forwarding', completion_evidence: 'EVID-006'},
        {priority: 'Short', action: 'Block phishing domain in email/web controls', type: 'Block', owner: 'SOC', due_date: '2026-09-26', status: 'Done', trigger: 'Do Now', linked_claim: 'CLAIM-001', expected_outcome: 'Prevent further access', completion_evidence: 'Change record SAMPLE-CR-001'},
        {priority: 'Short', action: 'Hunt all users for observed infrastructure', type: 'Hunt', owner: 'SOC', due_date: '2026-09-26', status: 'Done', trigger: 'Do Now', linked_gap: 'GAP-002', expected_outcome: 'Determine broader impact', completion_evidence: 'INV-002, INV-003, INV-005'},
        {priority: 'Short', action: 'Review MFA/session details', type: 'Investigate', owner: 'IAM', due_date: '2026-09-27', status: 'In Progress', trigger: 'Do Now', linked_gap: 'GAP-001', expected_outcome: 'Clarify compromise mechanism'},
        {priority: 'Medium', action: 'Develop identity detection for mailbox changes after anomalous authentication', type: 'Detection', owner: 'Detection Engineering', due_date: '2026-10-03', status: 'Todo', trigger: 'Monitor', linked_claim: 'CLAIM-003', expected_outcome: 'Improve future detection'}
    ],
    sources: [
        {name: 'Microsoft 365 Message Trace', tlp: 'AMBER', reliability: 'A', information_credibility: 'HIGH', date: '2026-09-24', url: 'SRC-001', type: 'INTERNAL_TELEMETRY', primacy: 'Primary', provenance: 'Direct'},
        {name: 'Secure Web Gateway logs', tlp: 'AMBER', reliability: 'A', information_credibility: 'HIGH', date: '2026-09-24', url: 'SRC-002', type: 'INTERNAL_TELEMETRY', primacy: 'Primary', provenance: 'Direct'},
        {name: 'Microsoft Entra ID sign-in logs', tlp: 'AMBER', reliability: 'A', information_credibility: 'HIGH', date: '2026-09-24', url: 'SRC-003', type: 'INTERNAL_TELEMETRY', primacy: 'Primary', provenance: 'Direct'},
        {name: 'Microsoft 365 Unified Audit Log', tlp: 'AMBER', reliability: 'A', information_credibility: 'HIGH', date: '2026-09-24', url: 'SRC-004', type: 'INTERNAL_TELEMETRY', primacy: 'Primary', provenance: 'Direct'},
        {name: 'User incident report', tlp: 'AMBER', reliability: 'B', information_credibility: 'MEDIUM', date: '2026-09-24', url: 'SRC-005', type: 'HUMAN_REPORT', primacy: 'Primary', provenance: 'Direct'},
        {name: 'Incident Response ticket IR-2026-441', tlp: 'AMBER', reliability: 'A', information_credibility: 'HIGH', date: '2026-09-24', url: 'SRC-006', type: 'INCIDENT_RECORD', primacy: 'Primary', provenance: 'Direct'}
    ],
    evidence_register: [
        {evidence_id: 'EVID-001', type: 'Email Message Trace', description: 'Phishing message delivery record for the affected user.', source_ref: 'SRC-001', observed_at: '2026-09-24T07:41', location: 'Message trace record SAMPLE-MT-001', collected_by: 'SOC', integrity: 'System-generated log record', notes: 'Sample-only evidence reference.'},
        {evidence_id: 'EVID-002', type: 'Proxy Event', description: 'User access to the phishing URL.', source_ref: 'SRC-002', observed_at: '2026-09-24T07:46', location: 'Proxy event SAMPLE-PX-002', collected_by: 'SOC', integrity: 'System-generated log record', notes: 'Proxy coverage limited to managed endpoints.'},
        {evidence_id: 'EVID-003', type: 'Identity Sign-In Event', description: 'Successful Microsoft 365 sign-in from the observed source IP.', source_ref: 'SRC-003', observed_at: '2026-09-24T07:48', location: 'Sign-in event SAMPLE-ID-003', collected_by: 'IAM', integrity: 'System-generated log record', notes: 'Reserved TEST-NET-3 IP used in this example.'},
        {evidence_id: 'EVID-004', type: 'Cloud Audit Event', description: 'Mailbox forwarding rule creation event.', source_ref: 'SRC-004', observed_at: '2026-09-24T07:52', location: 'Audit event SAMPLE-UA-004', collected_by: 'M365 Admin', integrity: 'System-generated audit event', notes: 'Forwarding rule was removed during containment.'},
        {evidence_id: 'EVID-006', type: 'Incident Ticket Entry', description: 'Containment action record for session revocation and mailbox-rule removal.', source_ref: 'SRC-006', observed_at: '2026-09-24T08:16', location: 'IR-TICKET-2026-441', collected_by: 'IR', integrity: 'Ticket history', notes: 'Sample incident record.'},
        {evidence_id: 'EVID-007', type: 'Identity Hunt Result', description: 'Tenant-wide search result for additional sign-ins from the observed source IP.', source_ref: 'SRC-003', observed_at: '2026-09-26T09:10', location: 'Hunt result INV-002', collected_by: 'CTI Analyst 01', integrity: 'Query result retained in workspace', notes: 'No additional account sign-ins identified.'},
        {evidence_id: 'EVID-008', type: 'Email Hunt Result', description: 'Message trace search result for additional messages from the observed sender/domain.', source_ref: 'SRC-001', observed_at: '2026-09-26T11:05', location: 'Hunt result INV-005', collected_by: 'CTI Analyst 01', integrity: 'Query result retained in workspace', notes: 'No additional matching messages identified.'}
    ],
    sharing_review: {
        internal_hostnames: true,
        internal_ips: true,
        user_identifiers: true,
        email_addresses: true,
        victim_infrastructure: true,
        sensitive_evidence: true,
        tlp_verified: true,
        recipients_verified: true,
        defanging_verified: true,
        reviewed_by: 'CTI Analyst 01',
        reviewed_at: '2026-09-26T16:10',
        notes: 'Sample sharing review: internal hostnames, user identifiers and victim endpoint details should be removed from partner-facing copies.'
    },
    recipients: [
        {name: 'Jean Dupont', role: 'SOC Lead', organization: 'ACME France', email: 'soc-lead@acme.example'},
        {name: 'Claire Martin', role: 'IAM Lead', organization: 'ACME France', email: 'iam-lead@acme.example'},
        {name: 'Alex Bernard', role: 'IR Lead', organization: 'ACME France', email: 'ir@acme.example'}
    ],
    feedback_contact: 'cti@acme.example',
    distribution_handling: 'TLP:AMBER. Distribution limited to internal security teams and explicitly authorized response partners. Internal user and endpoint identifiers must not be redistributed outside the organization.',
    disclaimer: 'This sample assessment reflects fictitious information available to the analyst as of 26 September 2026 16:00 UTC. Absence of observed activity outside the documented telemetry scope must not be interpreted as proof that the activity did not occur.',
    closure: {
        requirement_answered: 'PARTIAL',
        closed_at: '2026-09-26T16:10',
        decision_supported: 'Yes. Available evidence was sufficient to support account containment, infrastructure blocking and organization-wide retrospective hunting.',
        operational_outcome: 'Account sessions revoked, password reset, unauthorized mailbox rule removed, phishing domain blocked and organization-wide hunt completed with no additional matches in available telemetry.',
        actions_executed: 'ACT-001, ACT-002, ACT-003, ACT-004',
        remaining_gaps: 'GAP-001, GAP-003',
        consumer_feedback: 'SOC requested a reusable detection for mailbox-rule creation following anomalous authentication.',
        what_worked: 'Correlation of email, web, identity and cloud-audit telemetry quickly established a reliable sequence of events.',
        change_next_time: 'Increase proxy retention beyond 14 days and improve identity-session telemetry available to analysts.'
    }
};

function generateUniqueReference() {
    const year = new Date().getUTCFullYear();
    const used = new Set(getSavedReports().map(report => report.reference));
    let sequence = 1;
    used.forEach(reference => {
        const match = new RegExp(`^FLINT-${year}-(\\d+)$`).exec(reference || '');
        if (match) sequence = Math.max(sequence, Number(match[1]) + 1);
    });
    let reference;
    do reference = `FLINT-${year}-${String(sequence++).padStart(3, '0')}`; while (used.has(reference));
    return reference;
}

function markSharingReviewTimestamp(data) {
    const reviewedAt = document.getElementById('sharing_reviewed_at');
    if (!reviewedAt || reviewedAt.value) return;
    const sharing = data.sharing_review || {};
    const hasReview = Object.keys(sharing).some(key => (
        !['notes', 'reviewed_by', 'reviewed_at', 'workspace_updated_at'].includes(key) && sharing[key]
    ));
    if (hasReview) reviewedAt.value = new Date().toISOString().slice(0, 16);
}

// Save Workspace (server authoritative, local fallback)
function saveReport() {
    const reportData = collectFormData();
    
    if (!reportData.reference) {
        alert('Please generate a reference number first');
        return;
    }

    markSharingReviewTimestamp(reportData);
    const refreshedData = collectFormData();
    refreshedData.workspace_id = currentReportId || refreshedData.workspace_id || refreshedData.reference;
    refreshedData.schema = 'odysafe.intelligence_workspace.v1';
    refreshedData.schema_version = '1.0';
    refreshedData.workspace_updated_at = new Date().toISOString();

    fetch('/flash-report/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(refreshedData)
    })
    .then(async r => {
        const body = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(body.error || `Save failed (${r.status})`);
        return body;
    })
    .then(body => {
        currentReportId = body.workspace?.workspace_id || refreshedData.workspace_id;
        clearDraftStorage();
        loadServerReports();
        updateFieldStatus();
        const memoryStatus = body.memory_index_status === 'indexed' ? ' and indexed in CTI Memory' : ', but Memory indexing failed';
        showToast('Workspace saved' + memoryStatus);
    })
    .catch(err => {
        console.error('Workspace save failed:', err);
        saveReportLocally(refreshedData);
        showToast('Server save failed; saved locally');
    });
}

function saveReportLocally(reportData) {
    
    const reports = getSavedReports();
    
    // Check if editing existing report
    if (currentReportId) {
        const index = reports.findIndex(r => r.id === currentReportId);
        if (index !== -1) {
            reports[index] = {
                ...reportData,
                id: currentReportId,
                updatedAt: new Date().toISOString()
            };
            showToast('Report updated');
        }
    } else {
        // Create new report
        const newReport = {
            ...reportData,
            id: 'flint_' + Date.now(),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        reports.push(newReport);
        currentReportId = newReport.id;
        showToast('Report saved');
    }
    
    localStorage.setItem(REPORTS_STORAGE_KEY, JSON.stringify(reports));
    clearDraftStorage();
    renderSavedReportsList();
    updateFieldStatus();
}

// Get all saved reports
function getSavedReports() {
    const stored = localStorage.getItem(REPORTS_STORAGE_KEY);
    return stored ? JSON.parse(stored) : [];
}

function loadServerReports() {
    return fetch(WORKSPACE_API)
        .then(r => r.ok ? r.json() : Promise.reject(new Error(`List failed (${r.status})`)))
        .then(data => {
            serverReportsCache = (data.workspaces || []).map(item => ({
                ...item,
                id: item.workspace_id,
                createdAt: item.created_at,
                updatedAt: item.updated_at
            }));
            renderSavedReportsList();
        })
        .catch(err => {
            console.warn('Server workspace list unavailable:', err);
            renderSavedReportsList();
        });
}

// Load specific report
function loadReport(reportId) {
    if (serverReportsCache.some(r => r.id === reportId)) {
        fetch(`${WORKSPACE_API}/${encodeURIComponent(reportId)}`)
            .then(async r => {
                const body = await r.json().catch(() => ({}));
                if (!r.ok) throw new Error(body.error || `Load failed (${r.status})`);
                return body;
            })
            .then(record => {
                currentReportId = reportId;
                populateFormData(record.json_payload || {});
                showToast('Loaded ' + (record.reference || reportId));
                updateFieldStatus();
                closeHistoryDrawer();
                showBlock(1);
            })
            .catch(err => alert('Workspace load failed: ' + err.message));
        return;
    }

    const reports = getSavedReports();
    const report = reports.find(r => r.id === reportId);
    
    if (!report) {
        alert('Report not found');
        return;
    }
    
    currentReportId = reportId;
    populateFormData(report);
    showToast('Loaded ' + report.reference);
    updateFieldStatus();
    closeHistoryDrawer();
    showBlock(1);
}

// Delete saved report
function deleteReport(reportId, event) {
    event.stopPropagation();
    
    if (!confirm('Are you sure you want to delete this report?')) {
        return;
    }

    if (serverReportsCache.some(r => r.id === reportId)) {
        fetch(`${WORKSPACE_API}/${encodeURIComponent(reportId)}`, { method: 'DELETE' })
            .then(async r => {
                const body = await r.json().catch(() => ({}));
                if (!r.ok) throw new Error(body.error || `Delete failed (${r.status})`);
                if (currentReportId === reportId) currentReportId = null;
                loadServerReports();
                showToast('Workspace deleted');
            })
            .catch(err => alert('Workspace delete failed: ' + err.message));
        return;
    }
    
    const reports = getSavedReports().filter(r => r.id !== reportId);
    localStorage.setItem(REPORTS_STORAGE_KEY, JSON.stringify(reports));
    
    if (currentReportId === reportId) {
        currentReportId = null;
    }
    
    renderSavedReportsList();
}

// Create new report (clear form)
function createNewReport(force = false) {
    if (!force && (currentReportId || document.getElementById('subject')?.value?.trim())) {
        if (!confirm('Start a new report? Unsaved changes will be lost.')) {
            return;
        }
    }
    
    document.getElementById('flashReportForm').reset();
    currentReportId = null;
    clearDraftStorage();
    // Reset badges
    document.querySelectorAll('.badge-option').forEach(b => b.classList.remove('selected'));
    document.querySelectorAll('.badge-option[data-value="RED"]').forEach(b => b.classList.add('selected'));
    document.querySelectorAll('.badge-option[data-value="High"]').forEach(b => b.classList.add('selected'));
    document.querySelectorAll('.badge-option[data-value="Draft"]').forEach(b => b.classList.add('selected'));
    
    // Clear dynamic tables (keep one row each)
    document.querySelectorAll('.data-table tbody').forEach(tbody => {
        const rows = tbody.querySelectorAll('tr');
        for (let i = rows.length - 1; i > 0; i--) {
            rows[i].remove();
        }
    });
    
    // Clear detection rules (keep none)
    document.querySelectorAll('.rule-container').forEach(r => r.remove());

    // Clear hunt leads
    const huntLeadsContainer = document.getElementById('hunt-leads-container');
    if (huntLeadsContainer) huntLeadsContainer.innerHTML = '';
    ['claims-table', 'gaps-table', 'investigation-journal-table', 'mitre-details-table', 'attack-sequence-table', 'evidence-table'].forEach(id => {
        const tbody = document.querySelector(`#${id} tbody`);
        if (tbody) tbody.innerHTML = '';
    });
    
    // Clear takeaways
    const takeawayContainer = document.getElementById('takeaways-container');
	    takeawayContainer.innerHTML = `
	        <div class="takeaway-row">
	            <input type="text" class="takeaway-input" placeholder="Key point for decision makers">
	            <select class="takeaway-likelihood"><option>N/A</option><option>Remote Chance</option><option>Realistic Possibility</option><option>Likely</option><option>Very Likely</option><option>Almost Certain</option></select>
	            <select class="takeaway-confidence"><option>N/A</option><option>Low</option><option>Moderate</option><option>High</option></select>
	            <input type="text" class="takeaway-evidence" placeholder="Evidence reference">
            <button type="button" class="btn-remove" onclick="this.parentElement.remove();">×</button>
        </div>
    `;
    
    // Reset dates and reference
    const now = new Date();
    document.getElementById('reference').value = generateUniqueReference();
    const isoString = now.toISOString().slice(0, 16);
    document.getElementById('created_at').value = isoString;
    document.getElementById('updated_at').value = isoString;
    
    updateFieldStatus();
    showBlock(1);
    updateToolbarMeta();
    showToast('New report started');
}

function loadExampleWorkspace() {
    if (!confirm('Load the sample Intelligence Workspace? Current unsaved form values will be replaced.')) {
        return;
    }
    createNewReport(true);
    currentReportId = null;
    const sample = JSON.parse(JSON.stringify(SAMPLE_INTELLIGENCE_WORKSPACE));
    populateFormData(sample);
    document.getElementById('reference').value = sample.reference;
    document.getElementById('created_at').value = sample.created_at;
    document.getElementById('updated_at').value = '2026-09-26T16:10';
    clearDraftStorage();
    updateFieldStatus();
    showBlock(1);
    showToast('Sample workspace loaded. Edit it before saving or exporting.');
}

// Render saved reports list
function renderSavedReportsList() {
    const container = document.getElementById('reports-list');
    if (!container) return;
    const reports = serverReportsCache.length ? serverReportsCache : getSavedReports();
    
    if (reports.length === 0) {
        container.innerHTML = '<div class="reports-empty">No saved reports yet.</div>';
        return;
    }
    
    reports.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    
    container.innerHTML = reports.map(report => {
        const isActive = report.id === currentReportId;
        const createdDate = new Date(report.updatedAt || report.createdAt).toLocaleDateString();
        const safeId = report.id.replace(/'/g, "\\'");
        return `
            <div class="report-item ${isActive ? 'active' : ''}" onclick="loadReport('${safeId}')">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
                    <div style="min-width:0;flex:1;">
                        <div class="report-item-ref">${escHtml(report.reference || 'No reference')}</div>
                        <div class="report-item-meta">${escHtml(report.subject || 'No subject')} · ${createdDate}</div>
                        <div class="report-item-tags">
                            <span class="report-tag">${escHtml(report.status || 'Draft')}</span>
                            <span class="report-tag">${escHtml(report.investigation_status || report.priority || 'Workspace')}</span>
                        </div>
                    </div>
                    <button type="button" class="btn-remove" onclick="deleteReport('${safeId}', event)" title="Delete">×</button>
                </div>
            </div>
        `;
    }).join('');
}

// Collect all form data
function collectFormData() {
    const data = {
        // Basic fields
        reference: document.getElementById('reference')?.value || '',
        created_at: document.getElementById('created_at')?.value || '',
        updated_at: document.getElementById('updated_at')?.value || new Date().toISOString().slice(0, 16),
        author: document.getElementById('author')?.value || '',
        subject: document.getElementById('subject')?.value || '',
        product_type: document.getElementById('product_type')?.value || 'Intelligence Workspace',
        pir: document.getElementById('pir')?.value || '',
        purpose: document.getElementById('purpose')?.value || '',
        intelligence_requirement: document.getElementById('intelligence_requirement')?.value || '',
        requester: document.getElementById('requester')?.value || '',
        intended_consumers: document.getElementById('intended_consumers')?.value || '',
        decision_requirement: document.getElementById('decision_requirement')?.value || '',
        decision_deadline: document.getElementById('decision_deadline')?.value || '',
        deadline_reason: document.getElementById('deadline_reason')?.value || '',
        scope: document.getElementById('scope')?.value || '',
        
        // Selected badges
        tlp: document.querySelector('#tlp-selector .badge-option.selected')?.dataset.value || 'RED',
        pap: document.querySelector('#pap-selector .badge-option.selected')?.dataset.value || 'AMBER',
        priority: document.querySelector('#priority-selector .badge-option.selected')?.dataset.value || 'Medium',
        status: document.querySelector('#status-selector .badge-option.selected')?.dataset.value || 'Draft',
        incident_confidence: document.getElementById('incident_likelihood')?.value || 'Unknown',
        analytic_confidence: document.getElementById('analytic_confidence')?.value || '',
        investigation_status: document.getElementById('investigation_status')?.value || '',
        overall_confidence: document.getElementById('overall_likelihood')?.value || 'Unknown',
        overall_analytic_confidence: document.getElementById('overall_analytic_confidence')?.value || '',
        cves: document.getElementById('cves')?.value || '',
        incident_type: document.getElementById('incident_type')?.value || '',
        threat_actor: document.getElementById('threat_actor')?.value || '',
        attribution_basis: document.getElementById('attribution_basis')?.value || 'Unattributed',
        affected_entities: document.getElementById('affected_entities')?.value || '',
        threat_nature: document.getElementById('threat_nature')?.value || '',
        urgency_action: document.getElementById('urgency_action')?.value || '',
        observed_impact: document.getElementById('observed_impact')?.value || '',
        impact_confidentiality: document.getElementById('impact_confidentiality')?.value || '',
        impact_integrity: document.getElementById('impact_integrity')?.value || '',
        impact_availability: document.getElementById('impact_availability')?.value || '',
        initial_signal: document.getElementById('initial_signal')?.value || '',
        why_it_matters: document.getElementById('why_it_matters')?.value || '',
        required_action: document.getElementById('required_action')?.value || '',
        
        // Key judgements (the legacy takeaways array is kept below for old drafts)
        takeaways: Array.from(document.querySelectorAll('.takeaway-input')).map(i => i.value).filter(v => v),
        key_judgements: Array.from(document.querySelectorAll('.takeaway-row')).map(row => ({
            judgement: row.querySelector('.takeaway-input')?.value || '',
            likelihood: row.querySelector('.takeaway-likelihood')?.value || 'N/A',
            confidence: row.querySelector('.takeaway-confidence')?.value || 'N/A',
            evidence: row.querySelector('.takeaway-evidence')?.value || ''
        })).filter(item => item.judgement || item.evidence),
        
        // Diamond model
        diamond_adversary: document.getElementById('diamond_adversary')?.value || '',
        diamond_infrastructure: document.getElementById('diamond_infrastructure')?.value || '',
        diamond_capability: document.getElementById('diamond_capability')?.value || '',
        diamond_victim: document.getElementById('diamond_victim')?.value || '',
        
        // Technical details
        attack_vector: document.getElementById('attack_vector')?.value || '',
        malware_family: document.getElementById('malware_family')?.value || '',
        persistence: document.getElementById('persistence')?.value || '',
        c2_infrastructure: document.getElementById('c2_infrastructure')?.value || '',
        anchor: document.getElementById('anchor')?.value || '',
        working_hypothesis: document.getElementById('working_hypothesis')?.value || '',
        evidence_for: document.getElementById('evidence_for')?.value || '',
        evidence_against: document.getElementById('evidence_against')?.value || '',
        alternative_explanation: document.getElementById('alternative_explanation')?.value || '',
        next_best_pivot: document.getElementById('next_best_pivot')?.value || '',
        
        // Timeline block fields
        threat_history: document.getElementById('threat_history')?.value || '',
        affected_scope: document.getElementById('affected_scope')?.value || '',
        first_observed: document.getElementById('first_observed')?.value || '',
        patch_date: document.getElementById('patch_date')?.value || '',

        // Gaps
        known_unknowns: document.getElementById('known_unknowns')?.value || '',
        hunt_questions: document.getElementById('hunt_questions')?.value || '',
        rfis: document.getElementById('rfis')?.value || '',

        // Assessment block fields
        source_reliability: document.getElementById('source_reliability')?.value || '',
        biases: document.getElementById('biases')?.value || '',
        section_confidence: document.getElementById('section_confidence')?.value || '',
        detection_validation_status: document.getElementById('detection_validation_status')?.value || 'Draft',
        detection_telemetry: document.getElementById('detection_telemetry')?.value || '',
        detection_false_positives: document.getElementById('detection_false_positives')?.value || '',
        hunt_result: document.getElementById('hunt_result')?.value || '',
        hunt_new_artifacts: document.getElementById('hunt_new_artifacts')?.value || '',
        hunt_interpretation: document.getElementById('hunt_interpretation')?.value || '',
        hunt_follow_up: document.getElementById('hunt_follow_up')?.value || '',
        confidence_rationale: document.getElementById('confidence_rationale')?.value || '',
        key_assumptions: document.getElementById('key_assumptions')?.value || '',
        internal_relevance: {
            technology_relevance: document.getElementById('rel_technology')?.value || 'NOT_ASSESSED',
            affected_version_status: document.getElementById('rel_affected_version')?.value || 'NOT_ASSESSED',
            internet_exposure: document.getElementById('rel_internet_exposure')?.value || 'NOT_ASSESSED',
            sector_relevance: document.getElementById('rel_sector')?.value || 'NOT_ASSESSED',
            geographic_relevance: document.getElementById('rel_geographic')?.value || 'NOT_ASSESSED',
            supplier_relevance: document.getElementById('rel_supplier')?.value || 'NOT_ASSESSED',
            internal_observation: document.getElementById('rel_internal_observation')?.value || 'NOT_ASSESSED',
            overall_relevance: document.getElementById('rel_overall')?.value || 'UNKNOWN',
            relevance_decision: document.getElementById('rel_decision')?.value || 'UNKNOWN',
            rationale: document.getElementById('rel_rationale')?.value || '',
            assessed_by: document.getElementById('rel_assessed_by')?.value || '',
            assessed_at: document.getElementById('rel_assessed_at')?.value || ''
        },
        handoff: {
            current_situation: document.getElementById('handoff_current_situation')?.value || '',
            established_assessments: document.getElementById('handoff_established_assessments')?.value || '',
            outstanding_questions: document.getElementById('handoff_outstanding_questions')?.value || '',
            next_step: document.getElementById('handoff_next_step')?.value || '',
            blocked_by: document.getElementById('handoff_blocked_by')?.value || '',
            owner: document.getElementById('handoff_owner')?.value || '',
            warning: document.getElementById('handoff_warning')?.value || '',
            last_updated: new Date().toISOString().slice(0, 16)
        },

        // Distribution metadata
        feedback_contact: document.getElementById('feedback_contact')?.value || '',
        distribution_handling: document.getElementById('distribution_handling')?.value || '',
        disclaimer: document.getElementById('disclaimer')?.value || '',
        sharing_review: {
            internal_hostnames: document.getElementById('share_internal_hostnames')?.checked || false,
            internal_ips: document.getElementById('share_internal_ips')?.checked || false,
            user_identifiers: document.getElementById('share_user_identifiers')?.checked || false,
            email_addresses: document.getElementById('share_email_addresses')?.checked || false,
            victim_infrastructure: document.getElementById('share_victim_infrastructure')?.checked || false,
            sensitive_evidence: document.getElementById('share_sensitive_evidence')?.checked || false,
            tlp_verified: document.getElementById('share_tlp_verified')?.checked || false,
            recipients_verified: document.getElementById('share_recipients_verified')?.checked || false,
            defanging_verified: document.getElementById('share_defanging_verified')?.checked || false,
            reviewed_by: document.getElementById('sharing_reviewed_by')?.value || '',
            reviewed_at: document.getElementById('sharing_reviewed_at')?.value || '',
            workspace_updated_at: document.getElementById('updated_at')?.value || '',
            notes: document.getElementById('sharing_review_notes')?.value || ''
        },
        closure: {
            requirement_answered: document.getElementById('closure_requirement_answered')?.value || 'UNKNOWN',
            closed_at: document.getElementById('closure_closed_at')?.value || '',
            decision_supported: document.getElementById('closure_decision_supported')?.value || '',
            operational_outcome: document.getElementById('closure_operational_outcome')?.value || '',
            actions_executed: document.getElementById('closure_actions_executed')?.value || '',
            remaining_gaps: document.getElementById('closure_remaining_gaps')?.value || '',
            consumer_feedback: document.getElementById('closure_consumer_feedback')?.value || '',
            what_worked: document.getElementById('closure_what_worked')?.value || '',
            change_next_time: document.getElementById('closure_change_next_time')?.value || ''
        },

        // Tables
        iocs: [],
        data_availability: [],
        detection_rules: [],
        recommendations: [],
        timeline: [],
        sources: [],
        recipients: [],
        evidence_register: [],
        ttps: [],
        hunt_leads: [],
        mitre_details: [],
        attack_sequence: [],
        gaps: [],
        analytic_claims: [],
        investigation_journal: [],
        
        // Defang option
        defang_export: document.getElementById('defang_export')?.checked || false
    };
    
    // Collect IOCs
    document.querySelectorAll('#iocs-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input, select');
        if (inputs.length >= 16 && inputs[1]?.value?.trim()) {
            data.iocs.push({
                type: inputs[0]?.value || '',
                value: inputs[1]?.value || '',
                role: inputs[2]?.value || 'Unknown',
                artifact_context: inputs[3]?.value || 'UNKNOWN',
                tlp: inputs[4]?.value || '',
                confidence: inputs[5]?.value || '',
                origin: inputs[6]?.value || 'Unknown',
                first_seen: inputs[7]?.value || '',
                last_seen: inputs[8]?.value || '',
                last_validated: inputs[9]?.value || '',
                discriminative_value: inputs[10]?.value || 'UNKNOWN',
                false_positive_risk: inputs[11]?.value || 'UNKNOWN',
                operational_status: inputs[12]?.value || 'Unknown',
                recommended_use: inputs[13]?.value || 'Enrichment Only',
                review_date: inputs[14]?.value || '',
                context: inputs[15]?.value || '',
                id: row.dataset.iocId || null
            });
        }
    });

    document.querySelectorAll('#data-availability-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input, select');
        if (inputs.length >= 6 && inputs[0]?.value?.trim()) {
            data.data_availability = data.data_availability || [];
            data.data_availability.push({
                data_source: inputs[0]?.value || '',
                needed: inputs[1]?.value || 'YES',
                available: inputs[2]?.value || 'UNKNOWN',
                retention: inputs[3]?.value || '',
                coverage: inputs[4]?.value || '',
                limitation: inputs[5]?.value || ''
            });
        }
    });

    // Collect timeline
    document.querySelectorAll('#timeline-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input, select');
        if (inputs.length >= 6 && Array.from(inputs).some(input=>input.value?.trim())) {
            data.timeline.push({
                date: inputs[0]?.value || '',
                event: inputs[1]?.value || '',
                status: inputs[2]?.value || 'Observed',
                significance: inputs[3]?.value || 'Medium',
                source: inputs[4]?.value || '',
                evidence: inputs[5]?.value || ''
            });
        }
    });

    // Collect sources
    document.querySelectorAll('#sources-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input, select');
        if (inputs.length >= 9 && inputs[0]?.value?.trim()) {
            data.sources.push({
                name: inputs[0]?.value || '',
                tlp: inputs[1]?.value || 'AMBER',
                reliability: inputs[2]?.value || 'A',
                information_credibility: inputs[3]?.value || 'UNKNOWN',
                date: inputs[4]?.value || '',
                url: inputs[5]?.value || '',
                type: inputs[6]?.value || 'OTHER',
                primacy: inputs[7]?.value || 'Primary',
                provenance: inputs[8]?.value || 'Direct'
            });
        }
    });

    document.querySelectorAll('#evidence-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input');
        if (inputs.length >= 9 && inputs[0]?.value?.trim()) {
            data.evidence_register.push({
                evidence_id: inputs[0]?.value || '',
                type: inputs[1]?.value || '',
                description: inputs[2]?.value || '',
                source_ref: inputs[3]?.value || '',
                observed_at: inputs[4]?.value || '',
                location: inputs[5]?.value || '',
                collected_by: inputs[6]?.value || '',
                integrity: inputs[7]?.value || '',
                notes: inputs[8]?.value || ''
            });
        }
    });

    // Collect recipients
    document.querySelectorAll('#recipients-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input');
        if (inputs.length >= 4 && Array.from(inputs).some(input => input.value.trim())) {
            data.recipients.push({
                name: inputs[0]?.value || '',
                role: inputs[1]?.value || '',
                organization: inputs[2]?.value || '',
                email: inputs[3]?.value || ''
            });
        }
    });
    
    // Collect detection rules
    document.querySelectorAll('.rule-container').forEach(container => {
        const typeSelect = container.querySelector('.rule-type');
        const typeLabel = container.querySelector('[class^="rule-"]');
        const textarea = container.querySelector('textarea');
        if (textarea && textarea.value.trim()) {
            const ruleType = typeSelect ? typeSelect.value : (typeLabel ? typeLabel.textContent.split(' ')[0] : 'SIGMA');
            data.detection_rules.push({
                type: ruleType,
                name: ruleType + ' Rule',
                content: textarea.value,
                validation_status: data.detection_validation_status,
                telemetry: data.detection_telemetry,
                false_positives: data.detection_false_positives
            });
        }
    });

    document.querySelectorAll('.hunt-lead-row').forEach(row => {
        const lead = {};
        row.querySelectorAll('[data-hunt-field]').forEach(input => { lead[input.dataset.huntField] = input.value.trim(); });
        if (Object.values(lead).some(Boolean)) data.hunt_leads.push(lead);
    });
    
    // Collect recommendations
    document.querySelectorAll('#block-9 table tbody tr').forEach(row => {
        const selects = row.querySelectorAll('select');
        const inputs = row.querySelectorAll('input');
        if (selects.length >= 4 && inputs.length >= 3) {
            if (inputs[0]?.value?.trim()) data.recommendations.push({
                priority: selects[0]?.value || '',
                action: inputs[0]?.value || '',
                type: selects[1]?.value || '',
                owner: inputs[1]?.value || '',
                due_date: inputs[2]?.value || '',
                status: selects[2]?.value || 'Todo',
                trigger: selects[3]?.value || 'Do Now',
                linked_claim: inputs[3]?.value || '',
                linked_gap: inputs[4]?.value || '',
                expected_outcome: inputs[5]?.value || '',
                completion_evidence: inputs[6]?.value || ''
            });
        }
    });

    // Collect MITRE TTPs
    document.querySelectorAll('#ttps-container .ttp-chip').forEach(chip => {
        data.ttps.push({
            id: chip.dataset.id || '',
            name: chip.dataset.name || '',
            tactic: chip.dataset.tactic || ''
        });
    });
    document.querySelectorAll('#mitre-details-table tbody tr').forEach(row=>{const x=row.querySelectorAll('input,select');if(Array.from(x).some(i=>i.value?.trim()))data.mitre_details.push({technique:x[0]?.value||'',procedure:x[1]?.value||'',status:x[2]?.value||'Assessed',evidence:x[3]?.value||'',confidence:x[4]?.value||'Moderate'});});
    document.querySelectorAll('#attack-sequence-table tbody tr').forEach(row=>{const x=row.querySelectorAll('input');if(Array.from(x).some(i=>i.value?.trim()))data.attack_sequence.push({step:x[0]?.value||'',date:x[1]?.value||'',technique:x[2]?.value||'',procedure:x[3]?.value||'',evidence:x[4]?.value||''});});
    document.querySelectorAll('#claims-table tbody tr').forEach((row, index)=>{const x=row.querySelectorAll('input,select');if(Array.from(x).some(i=>i.value?.trim())){const status=x[1]?.value||'REPORTED';data.analytic_claims.push({claim_id:row.dataset.claimId||`CLAIM-${String(index+1).padStart(3,'0')}`,claim_text:x[0]?.value||'',analytical_status:status,source_refs:x[2]?.value||'',evidence_refs:x[3]?.value||'',rationale:status==='UNKNOWN'?'':(x[4]?.value||''),unknown_reason:status==='UNKNOWN'?(x[4]?.value||''):'',confidence:x[5]?.value||'Moderate',source_role:x[6]?.value||'UNKNOWN',source_independence:x[7]?.value||'UNKNOWN',depends_on_source:x[8]?.value||'',conflicts_with:x[9]?.value||'',decision_impact:x[10]?.value||'',increase_confidence_if:x[11]?.value||'',decrease_confidence_if:x[12]?.value||'',related_gap_id:x[13]?.value||''});}});
    document.querySelectorAll('#gaps-table tbody tr').forEach((row, index)=>{const x=row.querySelectorAll('input,select');if(Array.from(x).some(i=>i.value?.trim()))data.gaps.push({gap_id:x[0]?.value||`GAP-${String(index+1).padStart(3,'0')}`,question:x[1]?.value||'',gap:x[1]?.value||'',requirement_id:x[2]?.value||'',related_claim_id:x[3]?.value||'',why_it_matters:x[4]?.value||'',priority:x[5]?.value||'Medium',resolution:x[6]?.value||'',owner:x[7]?.value||'',status:x[8]?.value||'OPEN',resolution_summary:x[9]?.value||'',resolved_by_refs:x[10]?.value||'',resolved_at:x[11]?.value||''});});
    document.querySelectorAll('#investigation-journal-table tbody tr').forEach((row, index)=>{const x=row.querySelectorAll('input,select');if(Array.from(x).some(i=>i.value?.trim()))data.investigation_journal.push({entry_id:x[0]?.value||`JRN-${String(index+1).padStart(3,'0')}`,entry_type:x[1]?.value||'SEARCH',performed_at:x[2]?.value||'',analyst:x[3]?.value||'',input_refs:x[4]?.value||'',operation:x[5]?.value||'',tool_or_source:x[6]?.value||'',query_or_method:x[7]?.value||'',scope:x[8]?.value||'',time_window:x[9]?.value||'',result_type:x[10]?.value||'INCONCLUSIVE',result_summary:x[11]?.value||'',coverage:x[12]?.value||'',limitations:x[13]?.value||'',output_refs:x[14]?.value||'',next_step:x[15]?.value||''});});
    
    return data;
}

// Populate form with saved data
function populateFormData(data) {
    // Set basic fields
    if (data.reference) document.getElementById('reference').value = data.reference;
    if (data.created_at) document.getElementById('created_at').value = data.created_at;
    if (data.author) document.getElementById('author').value = data.author;
    if (data.subject) document.getElementById('subject').value = data.subject;
    if (data.product_type) {
        const productAliases = {'Flash Report':'Intelligence Workspace','Vulnerability Alert':'Vulnerability Intelligence Alert'};
        document.getElementById('product_type').value = productAliases[data.product_type] || data.product_type;
    }
    if (data.pir) document.getElementById('pir').value = data.pir;
    ['purpose','intelligence_requirement','requester','intended_consumers','decision_requirement','decision_deadline','deadline_reason','scope'].forEach(id=>{if(data[id] && document.getElementById(id))document.getElementById(id).value=data[id];});
    if (data.threat_actor) {
        document.getElementById('threat_actor').value = data.threat_actor;
        scheduleThreatActorHint();
    }
    if (data.attribution_basis) document.getElementById('attribution_basis').value = data.attribution_basis;
    if (data.cves) document.getElementById('cves').value = data.cves;
    if (data.incident_confidence) {
        const likelihoodMap = {'Confirmed': 'Almost Certain', 'Possible': 'Realistic Possibility'};
        document.getElementById('incident_likelihood').value = likelihoodMap[data.incident_confidence] || data.incident_confidence;
    }
    if (data.analytic_confidence) document.getElementById('analytic_confidence').value = data.analytic_confidence;
    if (data.investigation_status) document.getElementById('investigation_status').value = data.investigation_status;
    if (data.incident_type) document.getElementById('incident_type').value = data.incident_type;
    
    // Set textareas
    if (data.affected_entities) document.getElementById('affected_entities').value = data.affected_entities;
    if (data.threat_nature) document.getElementById('threat_nature').value = data.threat_nature;
    if (data.urgency_action) document.getElementById('urgency_action').value = data.urgency_action;
    if (data.diamond_adversary) document.getElementById('diamond_adversary').value = data.diamond_adversary;
    if (data.diamond_infrastructure) document.getElementById('diamond_infrastructure').value = data.diamond_infrastructure;
    if (data.diamond_capability) document.getElementById('diamond_capability').value = data.diamond_capability;
    if (data.diamond_victim) document.getElementById('diamond_victim').value = data.diamond_victim;
    if (data.attack_vector) document.getElementById('attack_vector').value = data.attack_vector;
    if (data.malware_family) document.getElementById('malware_family').value = data.malware_family;
    if (data.persistence) document.getElementById('persistence').value = data.persistence;
    if (data.c2_infrastructure) document.getElementById('c2_infrastructure').value = data.c2_infrastructure;
    if (data.anchor) document.getElementById('anchor').value = data.anchor;
    if (data.working_hypothesis) document.getElementById('working_hypothesis').value = data.working_hypothesis;
    if (data.evidence_for) document.getElementById('evidence_for').value = data.evidence_for;
    if (data.evidence_against) document.getElementById('evidence_against').value = data.evidence_against;
    if (data.alternative_explanation) document.getElementById('alternative_explanation').value = data.alternative_explanation;
    if (data.next_best_pivot) document.getElementById('next_best_pivot').value = data.next_best_pivot;
    if (data.initial_signal) document.getElementById('initial_signal').value = data.initial_signal;
    if (data.why_it_matters) document.getElementById('why_it_matters').value = data.why_it_matters;
    if (data.required_action) document.getElementById('required_action').value = data.required_action;
    
    // Block 5 fields
    if (data.threat_history) document.getElementById('threat_history').value = data.threat_history;
    if (data.affected_scope) document.getElementById('affected_scope').value = data.affected_scope;
    if (data.first_observed) document.getElementById('first_observed').value = data.first_observed;
    if (data.patch_date) document.getElementById('patch_date').value = data.patch_date;

    // Block 10 fields
    if (data.known_unknowns) document.getElementById('known_unknowns').value = data.known_unknowns;
    if (data.hunt_questions) document.getElementById('hunt_questions').value = data.hunt_questions;
    if (data.rfis) document.getElementById('rfis').value = data.rfis;

    // Block 11 fields
    if (data.source_reliability && document.getElementById('source_reliability')) document.getElementById('source_reliability').value = data.source_reliability;
    if (data.biases) document.getElementById('biases').value = data.biases;
    if (data.section_confidence) document.getElementById('section_confidence').value = data.section_confidence;
    if (data.overall_confidence) document.getElementById('overall_likelihood').value = data.overall_confidence;
    if (data.overall_analytic_confidence) document.getElementById('overall_analytic_confidence').value = data.overall_analytic_confidence;
    if (data.internal_relevance) {
        const rel = data.internal_relevance;
        const map = {rel_technology:'technology_relevance',rel_affected_version:'affected_version_status',rel_internet_exposure:'internet_exposure',rel_sector:'sector_relevance',rel_geographic:'geographic_relevance',rel_supplier:'supplier_relevance',rel_internal_observation:'internal_observation',rel_overall:'overall_relevance',rel_decision:'relevance_decision',rel_rationale:'rationale',rel_assessed_by:'assessed_by',rel_assessed_at:'assessed_at'};
        Object.entries(map).forEach(([id,key])=>{
            if(rel[key] && document.getElementById(id)) {
                document.getElementById(id).value = rel[key] === 'NOT_CHECKED' ? 'NOT_ASSESSED' : rel[key];
            }
        });
    }
    if (data.detection_validation_status) document.getElementById('detection_validation_status').value = data.detection_validation_status;
    if (data.detection_telemetry) document.getElementById('detection_telemetry').value = data.detection_telemetry;
    if (data.detection_false_positives) document.getElementById('detection_false_positives').value = data.detection_false_positives;
    ['observed_impact','hunt_result','hunt_new_artifacts','hunt_interpretation','hunt_follow_up','confidence_rationale','key_assumptions'].forEach(id=>{if(data[id] && document.getElementById(id))document.getElementById(id).value=data[id];});

    // Block 13 distribution metadata
    if (data.feedback_contact) document.getElementById('feedback_contact').value = data.feedback_contact;
    if (data.distribution_handling) document.getElementById('distribution_handling').value = data.distribution_handling;
    if (data.disclaimer) document.getElementById('disclaimer').value = data.disclaimer;
    if (data.sharing_review) {
        const s = data.sharing_review;
        const checks = {
            share_internal_hostnames: 'internal_hostnames',
            share_internal_ips: 'internal_ips',
            share_user_identifiers: 'user_identifiers',
            share_email_addresses: 'email_addresses',
            share_victim_infrastructure: 'victim_infrastructure',
            share_sensitive_evidence: 'sensitive_evidence',
            share_tlp_verified: 'tlp_verified',
            share_recipients_verified: 'recipients_verified',
            share_defanging_verified: 'defanging_verified'
        };
        Object.entries(checks).forEach(([id, key]) => { if (document.getElementById(id)) document.getElementById(id).checked = !!s[key]; });
        if (document.getElementById('sharing_reviewed_by')) document.getElementById('sharing_reviewed_by').value = s.reviewed_by || '';
        if (document.getElementById('sharing_reviewed_at')) document.getElementById('sharing_reviewed_at').value = toDatetimeLocal(s.reviewed_at || '');
        if (document.getElementById('sharing_review_notes')) document.getElementById('sharing_review_notes').value = s.notes || '';
    }
    if (data.closure) {
        const c = data.closure;
        const map = {closure_requirement_answered:'requirement_answered',closure_closed_at:'closed_at',closure_decision_supported:'decision_supported',closure_operational_outcome:'operational_outcome',closure_actions_executed:'actions_executed',closure_remaining_gaps:'remaining_gaps',closure_consumer_feedback:'consumer_feedback',closure_what_worked:'what_worked',closure_change_next_time:'change_next_time'};
        Object.entries(map).forEach(([id, key]) => { if (document.getElementById(id)) document.getElementById(id).value = c[key] || (id === 'closure_requirement_answered' ? 'UNKNOWN' : ''); });
    }
    if (data.handoff) {
        const h = data.handoff;
        const map = {handoff_current_situation:'current_situation',handoff_established_assessments:'established_assessments',handoff_outstanding_questions:'outstanding_questions',handoff_next_step:'next_step',handoff_blocked_by:'blocked_by',handoff_owner:'owner',handoff_warning:'warning'};
        Object.entries(map).forEach(([id,key])=>{if(h[key] && document.getElementById(id))document.getElementById(id).value=h[key];});
    }

    // Set selects
    if (data.impact_confidentiality) document.getElementById('impact_confidentiality').value = data.impact_confidentiality;
    if (data.impact_integrity) document.getElementById('impact_integrity').value = data.impact_integrity;
    if (data.impact_availability) document.getElementById('impact_availability').value = data.impact_availability;
    
    // Set badges
    if (data.tlp) {
        document.querySelectorAll('#tlp-selector .badge-option').forEach(b => b.classList.remove('selected'));
        const tlpBadge = document.querySelector(`#tlp-selector .badge-option[data-value="${data.tlp}"]`);
        if (tlpBadge) tlpBadge.classList.add('selected');
    }
    if (data.priority) {
        document.querySelectorAll('#priority-selector .badge-option').forEach(b => b.classList.remove('selected'));
        const priorityBadge = document.querySelector(`#priority-selector .badge-option[data-value="${data.priority}"]`);
        if (priorityBadge) priorityBadge.classList.add('selected');
    }
    if (data.status) {
        document.querySelectorAll('#status-selector .badge-option').forEach(b => b.classList.remove('selected'));
        const statusBadge = document.querySelector(`#status-selector .badge-option[data-value="${data.status}"]`);
        if (statusBadge) statusBadge.classList.add('selected');
    }
    
    // Set takeaways
    const savedJudgements=data.key_judgements || (data.takeaways || []).map(value=>({judgement:value,evidence:''}));
    if (savedJudgements.length > 0) {
        const container = document.getElementById('takeaways-container');
        container.innerHTML = '';
        savedJudgements.forEach(item => {
            const row = document.createElement('div');
            row.className = 'takeaway-row';
            row.innerHTML = `
                <input type="text" class="takeaway-input" value="${escHtml(item.judgement || '')}">
                <select class="takeaway-likelihood"><option>N/A</option><option>Remote Chance</option><option>Realistic Possibility</option><option>Likely</option><option>Very Likely</option><option>Almost Certain</option></select>
                <select class="takeaway-confidence"><option>N/A</option><option>Low</option><option>Moderate</option><option>High</option></select>
                <input type="text" class="takeaway-evidence" value="${escHtml(item.evidence || '')}" placeholder="Evidence reference">
                <button type="button" class="btn-remove" onclick="this.parentElement.remove(); updateFieldStatus();" aria-label="Remove takeaway">×</button>
            `;
            row.querySelector('.takeaway-likelihood').value = item.likelihood || 'N/A';
            row.querySelector('.takeaway-confidence').value = item.confidence || 'N/A';
            container.appendChild(row);
        });
    }

    // Set Timeline table rows
    if (data.timeline && data.timeline.length > 0) {
        const tbody = document.querySelector('#timeline-table tbody');
        tbody.innerHTML = '';
        data.timeline.forEach(event => {
            const row = document.createElement('tr');
            row.className = 'timeline-row';
            row.innerHTML = `
                <td><input type="datetime-local" value="${event.date || ''}"></td>
                <td><input type="text" placeholder="Event description" value="${(event.event || '').replace(/"/g, '&quot;')}"></td>
                <td>
                    <select>
                        <option ${event.status === 'Observed' ? 'selected' : ''}>Observed</option><option ${event.status === 'Reported' ? 'selected' : ''}>Reported</option><option ${event.status === 'Assessed' ? 'selected' : ''}>Assessed</option>
                    </select>
                </td>
                <td><select><option ${((event.significance || event.impact) === 'Critical') ? 'selected' : ''}>Critical</option><option ${((event.significance || event.impact) === 'High') ? 'selected' : ''}>High</option><option ${((event.significance || event.impact) === 'Medium') ? 'selected' : ''}>Medium</option><option ${((event.significance || event.impact) === 'Low') ? 'selected' : ''}>Low</option></select></td>
                <td><input type="text" placeholder="Source" value="${(event.source || '').replace(/"/g, '&quot;')}"></td>
                <td><input type="text" placeholder="Evidence reference" value="${escHtml(event.evidence || '')}"></td>
                ${FR_REMOVE_CELL}
            `;
            tbody.appendChild(row);
        });
    }

    if (data.data_availability && data.data_availability.length > 0) {
        const tbody = document.querySelector('#data-availability-table tbody');
        if (tbody) {
            tbody.innerHTML = '';
            data.data_availability.forEach(addDataAvailabilityRow);
        }
    }

    // Set Sources table rows
    if (data.sources && data.sources.length > 0) {
        const tbody = document.querySelector('#sources-table tbody');
        tbody.innerHTML = '';
        data.sources.forEach(src => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><input type="text" placeholder="Source name" value="${(src.name || '').replace(/"/g, '&quot;')}"></td>
                <td>
                    <select>
                        <option ${src.tlp === 'RED' ? 'selected' : ''}>RED</option>
                        <option ${src.tlp === 'AMBER' ? 'selected' : ''}>AMBER</option>
                        <option ${src.tlp === 'GREEN' ? 'selected' : ''}>GREEN</option>
                        <option ${src.tlp === 'CLEAR' ? 'selected' : ''}>CLEAR</option>
                    </select>
                </td>
                <td>
                    <select>
                        <option ${src.reliability === 'A' ? 'selected' : ''}>A</option>
                        <option ${src.reliability === 'B' ? 'selected' : ''}>B</option>
                        <option ${src.reliability === 'C' ? 'selected' : ''}>C</option>
                        <option ${src.reliability === 'D' ? 'selected' : ''}>D</option>
                        <option ${src.reliability === 'E' ? 'selected' : ''}>E</option>
                    </select>
                </td>
                <td><select><option ${src.information_credibility === 'UNKNOWN' ? 'selected' : ''}>UNKNOWN</option><option ${src.information_credibility === 'HIGH' ? 'selected' : ''}>HIGH</option><option ${src.information_credibility === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option><option ${src.information_credibility === 'LOW' ? 'selected' : ''}>LOW</option></select></td>
                <td><input type="date" value="${src.date || ''}"></td>
                <td><input type="text" list="cti_urls_list" placeholder="https://..." value="${(src.url || '').replace(/"/g, '&quot;')}"></td>
                <td>
                    <select>
                        <option ${src.type === 'INTERNAL_TELEMETRY' ? 'selected' : ''}>INTERNAL_TELEMETRY</option>
                        <option ${src.type === 'HUMAN_REPORT' ? 'selected' : ''}>HUMAN_REPORT</option>
                        <option ${src.type === 'INCIDENT_RECORD' ? 'selected' : ''}>INCIDENT_RECORD</option>
                        <option ${src.type === 'ADVISORY' || src.type === 'Advisory' ? 'selected' : ''}>ADVISORY</option>
                        <option ${src.type === 'VENDOR_REPORT' || src.type === 'Vendor' ? 'selected' : ''}>VENDOR_REPORT</option>
                        <option ${src.type === 'OSINT' ? 'selected' : ''}>OSINT</option>
                        <option ${src.type === 'OTHER' || src.type === 'Blog' || src.type === 'CERT' || src.type === 'Private' ? 'selected' : ''}>OTHER</option>
                    </select>
                </td>
                <td><select><option ${(src.primacy || src.provenance) === 'Primary' ? 'selected' : ''}>Primary</option><option ${(src.primacy || src.provenance) === 'Secondary' ? 'selected' : ''}>Secondary</option></select></td>
                <td><select><option ${src.provenance === 'Direct' ? 'selected' : ''}>Direct</option><option ${src.provenance === 'Derived' ? 'selected' : ''}>Derived</option><option ${src.provenance === 'Cited' ? 'selected' : ''}>Cited</option></select></td>
                ${FR_REMOVE_CELL}
            `;
            tbody.appendChild(row);
        });
    }

    if (data.evidence_register && data.evidence_register.length > 0) {
        const tbody = document.querySelector('#evidence-table tbody');
        if (tbody) {
            tbody.innerHTML = '';
            data.evidence_register.forEach(addEvidenceRow);
        }
    }

    // Set Recipients table rows
    if (data.recipients && data.recipients.length > 0) {
        const tbody = document.querySelector('#recipients-table tbody');
        tbody.innerHTML = '';
        data.recipients.forEach(rec => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><input type="text" placeholder="Full name" value="${(rec.name || '').replace(/"/g, '&quot;')}"></td>
                <td><input type="text" placeholder="CISO, SOC Lead..." value="${(rec.role || '').replace(/"/g, '&quot;')}"></td>
                <td><input type="text" placeholder="Organization" value="${(rec.organization || '').replace(/"/g, '&quot;')}"></td>
                <td><input type="email" placeholder="email@org.com" value="${(rec.email || '').replace(/"/g, '&quot;')}"></td>
                ${FR_REMOVE_CELL}
            `;
            tbody.appendChild(row);
        });
    }

    // Set IOCs
    if (data.iocs && data.iocs.length > 0) {
        const tbody = document.querySelector('#iocs-table tbody');
        tbody.innerHTML = '';
        data.iocs.forEach(ioc => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <select>
                        <option ${ioc.type === 'IP' ? 'selected' : ''}>IP</option>
                        <option ${ioc.type === 'Domain' ? 'selected' : ''}>Domain</option>
                        <option ${ioc.type === 'URL' ? 'selected' : ''}>URL</option>
                        <option ${ioc.type === 'Hash_MD5' ? 'selected' : ''}>Hash_MD5</option>
                        <option ${ioc.type === 'Hash_SHA1' ? 'selected' : ''}>Hash_SHA1</option>
                        <option ${ioc.type === 'Hash_SHA256' ? 'selected' : ''}>Hash_SHA256</option>
                        <option ${ioc.type === 'Email' ? 'selected' : ''}>Email</option>
                        <option ${ioc.type === 'CIDR' ? 'selected' : ''}>CIDR</option>
                    </select>
                </td>
                <td><input type="text" class="fr-cell-mono" placeholder="Value" value="${(ioc.value || '').replace(/"/g, '&quot;')}"></td>
                <td><select><option>C2</option><option>Payload</option><option>Phishing</option><option>Redirector</option><option>Scanner</option><option>Staging</option><option>Malware Delivery</option><option>Victim</option><option>Unknown</option></select></td>
                <td><select><option>UNKNOWN</option><option>ATTACKER_CONTROLLED</option><option>VICTIM_INTERNAL</option><option>BENIGN_ENVIRONMENT</option></select></td>
                <td>
                    <select>
                        <option ${ioc.tlp === 'RED' ? 'selected' : ''}>RED</option>
                        <option ${ioc.tlp === 'AMBER' ? 'selected' : ''}>AMBER</option>
                        <option ${ioc.tlp === 'GREEN' ? 'selected' : ''}>GREEN</option>
                    </select>
                </td>
                <td>
                    <select>
                        <option ${ioc.confidence === 'High' ? 'selected' : ''}>High</option>
                        <option ${ioc.confidence === 'Medium' ? 'selected' : ''}>Medium</option>
                        <option ${ioc.confidence === 'Low' ? 'selected' : ''}>Low</option>
                    </select>
                </td>
                <td><select><option>Observed</option><option>Reported</option><option>Derived</option><option>Imported</option><option>Unknown</option></select></td>
                <td><input type="date" value="${ioc.first_seen || ''}"></td>
                <td><input type="date" value="${ioc.last_seen || ''}"></td>
                <td><input type="date" value="${ioc.last_validated || ''}"></td>
                <td><select><option>UNKNOWN</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></td>
                <td><select><option>UNKNOWN</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></td>
                <td><select><option ${ioc.operational_status === 'Active' ? 'selected' : ''}>Active</option><option ${ioc.operational_status === 'Inactive' ? 'selected' : ''}>Inactive</option><option ${ioc.operational_status === 'Historical' ? 'selected' : ''}>Historical</option><option ${ioc.operational_status === 'Expired' ? 'selected' : ''}>Expired</option><option ${ioc.operational_status === 'Unknown' ? 'selected' : ''}>Unknown</option></select></td>
                <td><select><option>Hunt</option><option>Monitor</option><option>Detect</option><option>Block Candidate</option><option>Enrichment Only</option><option>Do Not Block</option></select></td>
                <td><input type="date" value="${ioc.review_date || ''}"></td>
                <td><input type="text" placeholder="Context / relationship" value="${escHtml(ioc.context || ioc.notes || '')}"></td>
                ${FR_REMOVE_CELL}
            `;
            row.dataset.iocId = ioc.id || '';
            const selects=row.querySelectorAll('select');
            selects[1].value=ioc.role === 'Malware' ? 'Malware Delivery' : (ioc.role || 'Unknown');
            selects[2].value=ioc.artifact_context || 'UNKNOWN';
            selects[5].value=ioc.origin || 'Unknown';
            selects[6].value=ioc.discriminative_value || 'UNKNOWN';
            selects[7].value=ioc.false_positive_risk || 'UNKNOWN';
            selects[9].value=ioc.recommended_use || 'Enrichment Only';
            tbody.appendChild(row);
        });
    }

    // Set TTPs
    if (data.ttps && data.ttps.length > 0) {
        renderTtpChips(data.ttps);
    }

    // Set Detection Rules
    if (data.detection_rules) {
        document.querySelectorAll('.rule-container').forEach(r => r.remove());
        data.detection_rules.forEach(rule => {
            const container = document.querySelector('#block-8 .form-group');
            const ruleDiv = document.createElement('div');
            ruleDiv.className = 'rule-container';
            ruleDiv.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <select class="rule-type" style="padding: 0.25rem 0.75rem; background: #7c3aed; color: white; border: none; border-radius: 4px;">
                        <option value="SIGMA" ${rule.type === 'SIGMA' ? 'selected' : ''} style="background: #7c3aed;">SIGMA</option>
                        <option value="YARA" ${rule.type === 'YARA' ? 'selected' : ''} style="background: #2563eb;">YARA</option>
                        <option value="KQL" ${rule.type === 'KQL' ? 'selected' : ''} style="background: #0891b2;">KQL</option>
                        <option value="SPL" ${rule.type === 'SPL' ? 'selected' : ''} style="background: #65a30d;">SPL</option>
                        <option value="Snort" ${rule.type === 'Snort' ? 'selected' : ''} style="background: #ea580c;">Snort</option>
                        <option value="HUNT_LOGIC" ${rule.type === 'HUNT_LOGIC' ? 'selected' : ''} style="background: #374151;">HUNT_LOGIC</option>
                        <option value="NOT_APPLICABLE" ${rule.type === 'NOT_APPLICABLE' ? 'selected' : ''} style="background: #6b7280;">NOT_APPLICABLE</option>
                    </select>
                    <button type="button" class="btn-remove" onclick="this.closest('.rule-container').remove(); updateFieldStatus();">×</button>
                </div>
                <textarea style="width: 100%; min-height: 120px; font-family: monospace; font-size: 0.85rem; background: rgba(20,15,35,0.9); color: #e9d5ff; padding: 1rem; border: 1px solid rgba(109,40,217,0.3); border-radius: 6px;" placeholder="Enter detection rule here...">${rule.content || ''}</textarea>
            `;
            container.insertBefore(ruleDiv, container.lastElementChild);
        });
    }

    document.getElementById('hunt-leads-container').innerHTML = '';
    (data.hunt_leads || []).forEach(addHuntLead);
    document.querySelector('#claims-table tbody').innerHTML=''; (data.analytic_claims || []).forEach(addClaimRow);
    document.querySelector('#mitre-details-table tbody').innerHTML=''; (data.mitre_details || []).forEach(addMitreDetailRow);
    document.querySelector('#attack-sequence-table tbody').innerHTML=''; (data.attack_sequence || []).forEach(addAttackSequenceRow);
    document.querySelector('#gaps-table tbody').innerHTML=''; (data.gaps || []).forEach(addGapRow);
    document.querySelector('#investigation-journal-table tbody').innerHTML=''; (data.investigation_journal || []).forEach(addJournalRow);

    // Set Recommendations
    if (data.recommendations && data.recommendations.length > 0) {
        const tbody = document.querySelector('#recommendations-table tbody');
        tbody.innerHTML = '';
        data.recommendations.forEach(rec => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <select>
                        <option value="Immediate" ${rec.priority === 'Immediate' ? 'selected' : ''}>Immediate</option>
                        <option value="Short" ${rec.priority === 'Short' ? 'selected' : ''}>Short term</option>
                        <option value="Medium" ${rec.priority === 'Medium' ? 'selected' : ''}>Medium term</option>
                    </select>
                </td>
                <td><input type="text" placeholder="Action description" value="${(rec.action || '').replace(/"/g, '&quot;')}"></td>
                <td>
                    <select>
                        <option ${rec.type === 'Patch' ? 'selected' : ''}>Patch</option>
                        <option ${rec.type === 'Block' ? 'selected' : ''}>Block</option>
                        <option ${rec.type === 'Monitor' ? 'selected' : ''}>Monitor</option>
                        <option ${rec.type === 'Isolate' ? 'selected' : ''}>Isolate</option>
                        <option ${rec.type === 'Hunt' ? 'selected' : ''}>Hunt</option>
                        <option ${rec.type === 'Notify' ? 'selected' : ''}>Notify</option>
                        <option ${rec.type === 'Escalate' ? 'selected' : ''}>Escalate</option>
                    </select>
                </td>
                <td><input type="text" placeholder="Team/Person" value="${(rec.owner || '').replace(/"/g, '&quot;')}"></td>
                <td><input type="date" value="${rec.due_date || ''}"></td>
                <td>
                    <select>
                        <option ${rec.status === 'Todo' ? 'selected' : ''}>Todo</option>
                        <option ${rec.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                        <option ${rec.status === 'Blocked' ? 'selected' : ''}>Blocked</option>
                        <option ${rec.status === 'Done' ? 'selected' : ''}>Done</option>
                        <option ${rec.status === 'Cancelled' ? 'selected' : ''}>Cancelled</option>
                    </select>
                </td>
                <td><select><option>Do Now</option><option>Do If Confirmed</option><option>Monitor</option><option>Optional</option></select></td>
                <td><input type="text" placeholder="CLAIM-001" value="${escHtml(rec.linked_claim || '')}"></td>
                <td><input type="text" placeholder="GAP-001" value="${escHtml(rec.linked_gap || '')}"></td>
                <td><input type="text" placeholder="Expected outcome" value="${escHtml(rec.expected_outcome || '')}"></td>
                <td><input type="text" placeholder="Evidence of completion" value="${escHtml(rec.completion_evidence || '')}"></td>
                ${FR_REMOVE_CELL}
            `;
            row.querySelectorAll('select')[3].value=rec.trigger || 'Do Now';
            tbody.appendChild(row);
        });
    }
    
    // Update timestamp
    document.getElementById('updated_at').value = new Date().toISOString().slice(0, 16);
}

// Update progress indicator
function updateProgressIndicator() {
    const sections = document.querySelectorAll('.flash-section');
    let filled = 0;
    let readinessFilled = 0;
    let readinessTotal = 0;
    
    sections.forEach((section, index) => {
        const status = checkSectionStatus(section);
        const step = document.querySelector('.wizard-step[data-step="' + (index + 1) + '"]');
        const requirement = sectionRequirement(section.id);
        
        if (step) {
            step.classList.remove('completed', 'partial', 'empty');
            step.dataset.requirement = requirement;
            if (status === 'complete') {
                step.classList.add('completed');
                filled++;
            } else if (status === 'partial') {
                step.classList.add('partial');
                filled += 0.5;
            }
            let badge = step.querySelector('.wizard-step-req');
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'wizard-step-req';
                step.appendChild(badge);
            }
            badge.textContent = requirement === 'required' ? 'Required' : requirement === 'recommended' ? 'Recommended' : 'Optional';
        }

        if (requirement === 'required') {
            readinessTotal += 1;
            if (status === 'complete') readinessFilled += 1;
            else if (status === 'partial') readinessFilled += 0.5;
        }
    });
    
    const percent = readinessTotal ? Math.round((readinessFilled / readinessTotal) * 100) : Math.round((filled / sections.length) * 100);
    const fill = document.getElementById('fr-progress-fill');
    const label = document.getElementById('fr-progress-percent');
    if (fill) fill.style.width = percent + '%';
    if (label) label.textContent = percent + '% ready';
    updateAnalystProgress();
}

const ANALYST_PROGRESS_HELP = {
    purpose: {
        title: 'Define why this investigation exists.',
        covers: 'Purpose Context, Intelligence Requirement, Consumer, Decision Requirement, Scope, Deadline.',
        sufficient: 'The analyst knows what question must be answered, for whom, and within what boundaries.',
        note: 'Purpose guides collection and assessment before the product is written.'
    },
    collection: {
        title: 'Determine what information is available and what still needs to be collected.',
        covers: 'Sources, Indicators, Collection / Data Availability Plan, source provenance.',
        sufficient: 'The analyst knows what data is available, what is missing, and the main collection limitations.',
        note: 'Coverage is not completeness. Missing data may be acceptable if it does not affect the requirement.'
    },
    analyze: {
        title: 'Turn collected information into supported analytical findings.',
        covers: 'Analytic Claims, Evidence, Timeline, Technical Analysis, ATT&CK mapping, Attack Sequence, hypotheses and contradictions.',
        sufficient: 'Important analytical statements are supported by evidence, sources or explicit reasoning.',
        note: 'OBSERVED, REPORTED, INFERRED and UNKNOWN must remain distinct.'
    },
    relevance: {
        title: 'Determine whether the intelligence matters to the organization.',
        covers: 'Internal Relevance and organizational applicability.',
        sufficient: 'The analyst can explain why the intelligence is relevant, not relevant, or still cannot be assessed.',
        note: 'Internal relevance is not threat severity and does not prove compromise.'
    },
    investigate: {
        title: 'Resolve important unknowns and test analytical hypotheses.',
        covers: 'Intelligence Gaps, Investigation Journal, Hunt Leads, Open Questions, RFIs and Handoff.',
        sufficient: 'Important unresolved questions have either been investigated, explicitly deferred, or documented as blocked.',
        note: 'NO_HIT means no match was found in the documented scope; it does not prove absence of activity.'
    },
    assess: {
        title: 'Form the analytical assessment from the available evidence.',
        covers: 'Key Judgements, Overall Assessment, Confidence Rationale, Assumptions, Alternative Explanations.',
        sufficient: 'The analyst can explain the main conclusion, why it is supported, how confident they are, and what could change the assessment.',
        note: 'Confidence is not probability. Probability is not impact.'
    },
    act: {
        title: 'Translate intelligence into operational recommendations.',
        covers: 'Actions, linked Claims/Gaps, owner, priority, due date, status and completion evidence.',
        sufficient: 'Relevant recommendations have an owner or are explicitly deferred / not applicable.',
        note: 'Recommendation does not mean execution. Expected outcome does not prove the outcome occurred.'
    },
    deliver: {
        title: 'Prepare the intelligence product for its intended audience and sharing channel.',
        covers: 'Executive Summary, Sharing Review, Distribution, TLP, recipients, handling instructions and exports.',
        sufficient: 'The product is understandable by the intended audience and has passed the required sharing checks.',
        note: 'Sharing should protect sensitive information without removing useful intelligence.'
    },
    close: {
        title: 'Close the investigation and preserve what should be learned from it.',
        covers: 'Feedback / Closure, unresolved gaps, operational outcome and follow-up requirements.',
        sufficient: 'The analyst has documented the outcome, remaining uncertainties and required follow-up.',
        note: 'Closed does not mean everything is known.'
    }
};

function analystProgressDefinitions() {
    const claimCount = document.querySelectorAll('#claims-table tbody tr').length;
    const evidenceCount = document.querySelectorAll('#evidence-table tbody tr').length;
    const gapRows = Array.from(document.querySelectorAll('#gaps-table tbody tr'));
    const actionRows = Array.from(document.querySelectorAll('#recommendations-table tbody tr'));
    const openHighGaps = gapRows.filter(row => {
        const fields = row.querySelectorAll('input, select');
        return fields[5]?.value === 'High' && fields[8]?.value !== 'RESOLVED';
    }).length;
    const completedActionsMissingEvidence = actionRows.some(row => {
        const selects = row.querySelectorAll('select');
        const inputs = row.querySelectorAll('input');
        return selects[2]?.value === 'Done' && !inputs[6]?.value?.trim();
    });
    return {
        purpose: [
            ['Purpose documented', !!document.getElementById('purpose')?.value?.trim()],
            ['Requirement documented', !!document.getElementById('intelligence_requirement')?.value?.trim()],
            ['Consumer documented', !!document.getElementById('intended_consumers')?.value?.trim()],
            ['Decision requirement documented', !!document.getElementById('decision_requirement')?.value?.trim()],
            ['Scope documented', !!document.getElementById('scope')?.value?.trim()]
        ],
        collection: [
            ['Sources documented', SECTION_RULES['block-12']()],
            ['Indicators reviewed', SECTION_RULES['block-7']()],
            ['Data availability assessed', Array.from(document.querySelectorAll('#data-availability-table tbody tr')).some(row => row.querySelector('input')?.value?.trim())],
            ['Collection limitations documented when applicable', Array.from(document.querySelectorAll('#data-availability-table tbody tr')).some(row => row.querySelectorAll('input')[3]?.value?.trim())]
        ],
        analyze: [
            ['Claims documented', claimCount > 0],
            ['Evidence registered', evidenceCount > 0],
            ['Timeline documented', SECTION_RULES['block-5']()],
            ['Technical analysis present', SECTION_RULES['block-6']()],
            ['Alternative explanations assessed', !!document.getElementById('alternative_explanation')?.value?.trim()]
        ],
        relevance: [
            ['Internal relevance assessed', SECTION_RULES['block-11']()],
            ['Rationale documented', !!document.getElementById('rel_rationale')?.value?.trim()],
            ['Assessor documented', !!document.getElementById('rel_assessed_by')?.value?.trim()]
        ],
        investigate: [
            ['Intelligence gaps documented', gapRows.length > 0],
            ['Journal entries recorded', document.querySelectorAll('#investigation-journal-table tbody tr').length > 0],
            ['Hunt leads documented', document.querySelectorAll('#hunt-leads-container .hunt-lead-row').length > 0],
            ['High-priority gaps resolved or accepted', openHighGaps === 0],
            ['Handoff updated', !!document.getElementById('handoff_current_situation')?.value?.trim()]
        ],
        assess: [
            ['Key judgements documented', Array.from(document.querySelectorAll('.takeaway-input')).some(i => i.value.trim())],
            ['Overall probability assessed', !!document.getElementById('overall_likelihood')?.value?.trim()],
            ['Analytic confidence assessed', !!document.getElementById('overall_analytic_confidence')?.value?.trim()],
            ['Confidence rationale documented', !!document.getElementById('confidence_rationale')?.value?.trim()],
            ['Assumptions or contradictions documented', !!(document.getElementById('key_assumptions')?.value?.trim() || document.getElementById('biases')?.value?.trim())]
        ],
        act: [
            ['Actions documented', SECTION_RULES['block-9']()],
            ['Owners assigned', actionRows.some(row => row.querySelectorAll('input')[1]?.value?.trim())],
            ['Expected outcomes documented', actionRows.some(row => row.querySelectorAll('input')[5]?.value?.trim())],
            ['Completion evidence recorded where completed', !completedActionsMissingEvidence]
        ],
        deliver: [
            ['Summary drafted', SECTION_RULES['block-3']()],
            ['Recipients documented when required', Array.from(document.querySelectorAll('#recipients-table tbody tr')).some(row => row.querySelector('input')?.value?.trim())],
            ['Sharing review completed', Array.from(document.querySelectorAll('#block-13 input[type="checkbox"]')).some(input => input.checked)],
            ['TLP verified', !!document.getElementById('share_tlp_verified')?.checked],
            ['Handling instructions documented', !!document.getElementById('distribution_handling')?.value?.trim()]
        ],
        close: [
            ['Requirement answer recorded', !['UNKNOWN', ''].includes(document.getElementById('closure_requirement_answered')?.value || '')],
            ['Operational outcome documented', !!document.getElementById('closure_operational_outcome')?.value?.trim()],
            ['Remaining gaps documented when applicable', !!document.getElementById('closure_remaining_gaps')?.value?.trim()],
            ['Lessons or feedback documented', !!(document.getElementById('closure_consumer_feedback')?.value?.trim() || document.getElementById('closure_what_worked')?.value?.trim() || document.getElementById('closure_change_next_time')?.value?.trim())]
        ]
    };
}

function analystProgressStatus(items, key) {
    const done = items.filter(([, ok]) => ok).length;
    if (done === 0) return 'NOT STARTED';
    if (key === 'deliver' && isSharingReviewOutdated()) return 'NEEDS REVIEW';
    if (done === items.length) return 'SUFFICIENT';
    return 'IN PROGRESS';
}

function updateAnalystProgress() {
    const definitions = analystProgressDefinitions();
    document.querySelectorAll('.fr-progress-step').forEach(button => {
        const key = button.dataset.progressStep;
        const items = definitions[key] || [];
        const status = analystProgressStatus(items, key);
        const statusEl = button.querySelector('span');
        if (statusEl) statusEl.textContent = status;
        button.classList.remove('status-not-started', 'status-in-progress', 'status-sufficient', 'status-needs-review');
        button.classList.add('status-' + status.toLowerCase().replaceAll(' ', '-'));
    });
}

function renderAnalystProgressTooltip(key, anchor) {
    const tooltip = document.getElementById('analyst-progress-tooltip');
    const help = ANALYST_PROGRESS_HELP[key];
    const items = analystProgressDefinitions()[key] || [];
    if (!tooltip || !help) return;
    const status = analystProgressStatus(items, key);
    tooltip.innerHTML = `
        <strong>${escHtml(key.charAt(0).toUpperCase() + key.slice(1))} - ${escHtml(status)}</strong>
        <div>${escHtml(help.title)}</div>
        <div style="margin-top:8px;"><strong>Coverage</strong></div>
        <ul>${items.map(([label, ok]) => `<li>${ok ? 'OK' : 'TODO'} - ${escHtml(label)}</li>`).join('')}</ul>
        <div><strong>Covers</strong></div>
        <div>${escHtml(help.covers)}</div>
        <div style="margin-top:8px;"><strong>Sufficient when</strong></div>
        <div>${escHtml(help.sufficient)}</div>
        <div style="margin-top:8px;">${escHtml(help.note)}</div>
    `;
    tooltip.classList.add('is-visible');
    if (anchor) {
        const rect = anchor.getBoundingClientRect();
        const width = Math.min(360, Math.max(260, window.innerWidth - 32));
        const left = Math.min(rect.right + 12, window.innerWidth - width - 16);
        const top = Math.min(Math.max(rect.top - 4, 16), window.innerHeight - tooltip.offsetHeight - 16);
        tooltip.style.width = width + 'px';
        tooltip.style.left = Math.max(16, left) + 'px';
        tooltip.style.top = Math.max(16, top) + 'px';
    }
}

function hideAnalystProgressTooltip() {
    const tooltip = document.getElementById('analyst-progress-tooltip');
    if (tooltip) tooltip.classList.remove('is-visible');
}

function initAnalystProgressInteractions() {
    const tooltip = document.getElementById('analyst-progress-tooltip');
    if (tooltip && tooltip.parentElement !== document.body) {
        document.body.appendChild(tooltip);
    }
    document.querySelectorAll('.fr-progress-step').forEach(button => {
        const show = () => renderAnalystProgressTooltip(button.dataset.progressStep, button);
        button.addEventListener('mouseenter', show);
        button.addEventListener('focus', show);
        button.addEventListener('mouseleave', hideAnalystProgressTooltip);
        button.addEventListener('blur', hideAnalystProgressTooltip);
        button.addEventListener('click', () => showBlock(Number(button.dataset.targetStep || 1)));
    });
}

const SECTION_RULES = {
    'block-1': () => ['author','purpose','intelligence_requirement','intended_consumers','decision_requirement','scope'].every(id => !!document.getElementById(id)?.value?.trim()),
    'block-2': () => ['subject', 'incident_type', 'investigation_status'].every(id => !!document.getElementById(id)?.value?.trim()),
    'block-3': () => {
        const fields = ['affected_entities', 'threat_nature', 'urgency_action'];
        return fields.some(id => document.getElementById(id)?.value?.trim());
    },
    'block-4': () => Array.from(document.querySelectorAll('.takeaway-input')).some(i => i.value.trim()) || Array.from(document.querySelectorAll('#claims-table tbody tr')).some(row => {
        const claim = row.querySelector('td:first-child input');
        return claim && claim.value.trim();
    }),
    'block-5': () => {
        const fields = ['threat_history', 'affected_scope', 'first_observed', 'patch_date'];
        const hasField = fields.some(id => document.getElementById(id)?.value?.trim());
        const hasTimeline = Array.from(document.querySelectorAll('#timeline-table tbody tr')).some(row => {
            const inputs = row.querySelectorAll('input');
            return Array.from(inputs).some(i => i.value.trim());
        });
        return hasField || hasTimeline;
    },
    'block-6': () => {
        const ttps = document.querySelectorAll('#ttps-container .ttp-chip').length;
        const fields = ['diamond_adversary', 'diamond_infrastructure', 'diamond_capability', 'diamond_victim',
            'attack_vector', 'malware_family', 'persistence', 'c2_infrastructure'];
        return ttps > 0 || fields.some(id => document.getElementById(id)?.value?.trim());
    },
    'block-7': () => Array.from(document.querySelectorAll('#iocs-table tbody tr')).some(row => {
        const valInput = row.querySelector('td:nth-child(2) input');
        return valInput && valInput.value.trim();
    }),
    'block-8': () => Array.from(document.querySelectorAll('#block-8 .rule-container textarea, #block-8 .hunt-lead-row textarea, #block-8 .hunt-lead-row input')).some(t => t.value.trim()),
    'block-9': () => Array.from(document.querySelectorAll('#block-9 tbody tr')).some(row => {
        const action = row.querySelector('td:nth-child(2) input');
        return action && action.value.trim();
    }),
    'block-10': () => ['known_unknowns', 'hunt_questions', 'rfis', 'handoff_current_situation', 'handoff_next_step', 'handoff_blocked_by', 'handoff_owner', 'handoff_warning'].some(id => document.getElementById(id)?.value?.trim()) || Array.from(document.querySelectorAll('#gaps-table tbody tr, #investigation-journal-table tbody tr')).some(row => Array.from(row.querySelectorAll('input')).some(input => input.value.trim())),
    'block-11': () => ['biases', 'section_confidence', 'overall_likelihood', 'overall_analytic_confidence', 'rel_rationale', 'rel_assessed_by', 'rel_assessed_at'].some(id => document.getElementById(id)?.value?.trim()) || ['rel_technology','rel_affected_version','rel_internet_exposure','rel_sector','rel_geographic','rel_supplier','rel_internal_observation'].some(id => !['NOT_ASSESSED',''].includes(document.getElementById(id)?.value || '')) || !['UNKNOWN',''].includes(document.getElementById('rel_decision')?.value || ''),
    'block-12': () => Array.from(document.querySelectorAll('#sources-table tbody tr')).some(row => {
        const name = row.querySelector('input');
        return name && name.value.trim();
    }),
    'block-13': () => {
        const hasRecipient = Array.from(document.querySelectorAll('#recipients-table tbody tr')).some(row => {
            const name = row.querySelector('input');
            return name && name.value.trim();
        });
        const fields = ['feedback_contact', 'distribution_handling', 'disclaimer', 'sharing_review_notes', 'sharing_reviewed_by', 'sharing_reviewed_at', 'closure_decision_supported', 'closure_operational_outcome', 'closure_actions_executed', 'closure_remaining_gaps', 'closure_consumer_feedback', 'closure_what_worked', 'closure_change_next_time', 'closure_closed_at'];
        const hasSharingReview = Array.from(document.querySelectorAll('#block-13 input[type="checkbox"]')).some(input => input.checked);
        return hasRecipient || hasSharingReview || fields.some(id => document.getElementById(id)?.value?.trim()) || !['UNKNOWN',''].includes(document.getElementById('closure_requirement_answered')?.value || '');
    }
};

const OPTIONAL_SECTIONS = new Set(['block-8', 'block-10', 'block-11']);

// Check section status
function checkSectionStatus(section) {
    const rule = SECTION_RULES[section.id];
    if (!rule) return 'empty';
    if (rule()) return 'complete';
    if (OPTIONAL_SECTIONS.has(section.id)) return 'empty';
    const hasAny = Array.from(section.querySelectorAll('input:not([readonly]):not([type=checkbox]), textarea')).some(el => el.value && String(el.value).trim());
    return hasAny ? 'partial' : 'empty';
}

// Update field status
function updateFieldStatus() {
    document.querySelectorAll('.flash-section').forEach(section => {
        const statusEl = section.querySelector('.section-status');
        if (statusEl) {
            const status = checkSectionStatus(section);
            const requirement = sectionRequirement(section.id);
            statusEl.className = 'section-status status-' + status;
            statusEl.textContent = status === 'complete' ? 'Complete' : status === 'partial' ? 'Partial' : requirement === 'required' ? 'Required' : requirement === 'recommended' ? 'Recommended' : 'Optional';
        }
    });
    const missingHint=document.getElementById('block-2-missing');
    if (missingHint) {
        const labels={subject:'Subject',incident_type:'Threat / Activity Type',investigation_status:'Investigation Status'};
        const missing=Object.keys(labels).filter(id=>!document.getElementById(id)?.value?.trim()).map(id=>labels[id]);
        missingHint.hidden=!missing.length;
        missingHint.textContent=missing.length ? `Required to complete this section: ${missing.join(', ')}` : '';
    }
    updateProgressIndicator();
    updateToolbarMeta();
    const sharingWarning = document.getElementById('sharing-review-warning');
    if (sharingWarning) sharingWarning.style.display = isSharingReviewOutdated() ? 'block' : 'none';
}

// ==================== EXPORT FUNCTIONS ====================

function validateFlashReportData(data) {
    const errors = [];
    const warnings = [];
    const requiredContext = [
        ['purpose', 'Purpose'],
        ['intelligence_requirement', 'Intelligence Requirement'],
        ['intended_consumers', 'Intended Consumers'],
        ['decision_requirement', 'Decision Requirement'],
        ['subject', 'Subject'],
        ['scope', 'Scope']
    ];
    requiredContext.forEach(([key, label]) => {
        if (!String(data[key] || '').trim()) errors.push(`${label} is required for the purpose context.`);
    });

    const profile = PRODUCT_SECTION_PROFILE[data.product_type] || PRODUCT_SECTION_PROFILE['Intelligence Workspace'];
    (profile.required || []).forEach(sectionId => {
        const section = document.getElementById(sectionId);
        if (section && checkSectionStatus(section) !== 'complete') {
            const label = section.querySelector('h2')?.textContent?.replace(/\s+(Complete|Partial|Required|Recommended|Optional|Incomplete)\s*$/, '').trim() || sectionId;
            errors.push(`${label} is required for ${data.product_type || 'the selected product type'}.`);
        }
    });

    (data.analytic_claims || []).forEach((claim, index) => {
        const label = claim.claim_id || `Claim ${index + 1}`;
        const text = String(claim.claim_text || '').trim();
        const status = claim.analytical_status;
        if (!text) errors.push(`${label} requires claim text.`);
        if (status === 'OBSERVED' && !String(claim.evidence_refs || '').trim()) errors.push(`${label}: OBSERVED requires evidence references.`);
        if (status === 'REPORTED' && !String(claim.source_refs || '').trim()) errors.push(`${label}: REPORTED requires at least one source reference.`);
        if (status === 'INFERRED' && !String(claim.rationale || '').trim()) errors.push(`${label}: INFERRED requires rationale.`);
        if (status === 'UNKNOWN' && !String(claim.unknown_reason || '').trim()) warnings.push(`${label}: UNKNOWN should include an unknown reason.`);
        if (claim.source_independence === 'DEPENDENT' && !String(claim.depends_on_source || '').trim()) warnings.push(`${label}: DEPENDENT source independence should identify the upstream source.`);
        if (String(claim.conflicts_with || '').trim() && !String(claim.rationale || claim.unknown_reason || '').trim()) warnings.push(`${label}: contradictory claims should include a reason or note.`);
    });

    (data.iocs || []).forEach((ioc, index) => {
        const label = ioc.value || `Indicator ${index + 1}`;
        const use = String(ioc.recommended_use || '').toUpperCase();
        const fpRisk = String(ioc.false_positive_risk || 'UNKNOWN').toUpperCase();
        if (use === 'BLOCK CANDIDATE' || use === 'BLOCK_CANDIDATE') {
            if (!String(ioc.confidence || '').trim()) errors.push(`${label}: Block Candidate requires confidence.`);
            if (!String(ioc.false_positive_risk || '').trim() || fpRisk === 'UNKNOWN') errors.push(`${label}: Block Candidate requires false positive risk.`);
            if (!String(ioc.last_validated || '').trim()) errors.push(`${label}: Block Candidate requires last validated date.`);
            if (!String(ioc.context || '').trim()) errors.push(`${label}: Block Candidate requires context or relationship.`);
            if (fpRisk === 'HIGH') warnings.push(`${label}: high false-positive risk. Blocking may affect legitimate activity.`);
        }
        if ((ioc.operational_status || '').toUpperCase() === 'EXPIRED' && (use === 'BLOCK CANDIDATE' || use === 'BLOCK_CANDIDATE')) {
            warnings.push(`${label}: expired indicator is still marked as Block Candidate.`);
        }
    });

    (data.recommendations || []).forEach((action, index) => {
        const label = action.action || `Action ${index + 1}`;
        if ((action.priority === 'Immediate' || action.trigger === 'Do Now') && !String(action.owner || '').trim()) {
            errors.push(`${label}: immediate action requires an owner.`);
        }
        if (action.status === 'Done' && !String(action.completion_evidence || '').trim()) {
            warnings.push(`${label}: completed action should include completion evidence.`);
        }
    });

    (data.gaps || []).forEach((gap, index) => {
        const label = gap.gap_id || `Gap ${index + 1}`;
        if (!String(gap.question || gap.gap || '').trim()) errors.push(`${label} requires a question.`);
        if (!String(gap.why_it_matters || '').trim()) warnings.push(`${label} should explain why it matters.`);
        if (!String(gap.requirement_id || data.intelligence_requirement || '').trim()) warnings.push(`${label} should be linked to an intelligence requirement.`);
        if (gap.status === 'RESOLVED' && !String(gap.resolution_summary || '').trim()) errors.push(`${label}: RESOLVED requires a resolution summary.`);
    });

    const relevance = data.internal_relevance || {};
    if (relevance.overall_relevance && relevance.overall_relevance !== 'UNKNOWN' && !String(relevance.rationale || '').trim()) {
        warnings.push('Internal relevance should include rationale when the overall relevance is assessed.');
    }
    if (relevance.internal_observation === 'NO' && !String(relevance.rationale || '').trim()) {
        warnings.push('Internal observation set to NO should describe scope, telemetry, or search limits.');
    }
    if (relevance.relevance_decision === 'IMMEDIATE_ACTION' && !String(relevance.rationale || '').trim()) {
        warnings.push('Internal relevance decision IMMEDIATE_ACTION should include rationale.');
    }

    (data.investigation_journal || []).forEach((entry, index) => {
        const label = entry.entry_id || `Journal entry ${index + 1}`;
        if (entry.result_type === 'NO_HIT') {
            if (!String(entry.scope || '').trim()) errors.push(`${label}: NO_HIT requires scope.`);
            if (!String(entry.time_window || '').trim()) errors.push(`${label}: NO_HIT requires time window.`);
            if (!String(entry.tool_or_source || '').trim()) errors.push(`${label}: NO_HIT requires telemetry, tool, or data source.`);
            if (!String(entry.query_or_method || '').trim()) errors.push(`${label}: NO_HIT requires query or method.`);
            if (!String(entry.coverage || '').trim()) warnings.push(`${label}: NO_HIT should include coverage.`);
            if (!String(entry.limitations || '').trim()) warnings.push(`${label}: NO_HIT should include limitations.`);
        }
        if (entry.result_type === 'NO_DATA' && !String(entry.limitations || '').trim()) warnings.push(`${label}: NO_DATA should explain the data or visibility gap.`);
    });
    if (data.tlp === 'RED' && !(data.recipients || []).some(rec => String(rec.name || rec.email || '').trim())) {
        errors.push('TLP:RED requires at least one named recipient.');
    }
    const sharing = data.sharing_review || {};
    if (data.tlp === 'RED' && !sharing.recipients_verified) {
        errors.push('TLP:RED requires named recipients to be verified in Sharing Review.');
    }
    if (!sharing.tlp_verified) warnings.push('Sharing Review should verify TLP before distribution.');
    if (data.defang_export && !sharing.defanging_verified) warnings.push('Sharing Review should verify defanging when defanged export is enabled.');
    if (sharing.reviewed_at && data.updated_at && new Date(data.updated_at) > new Date(sharing.reviewed_at)) {
        warnings.push('Sharing Review is outdated because the workspace changed after review.');
    }
    return { errors, warnings };
}

function formatQualityResults(results) {
    const lines = [];
    if (!results.errors.length && !results.warnings.length) {
        return 'Analytic Quality Checks\n\nNo blocking issues or warnings found.';
    }
    if (results.errors.length) {
        lines.push('ERRORS');
        results.errors.forEach(item => lines.push('- ' + item));
    }
    if (results.warnings.length) {
        if (lines.length) lines.push('');
        lines.push('WARNINGS');
        results.warnings.forEach(item => lines.push('- ' + item));
    }
    return 'Analytic Quality Checks\n\n' + lines.join('\n');
}

function runQualityCheck() {
    alert(formatQualityResults(validateFlashReportData(collectFormData())));
}

function exportJsonWorkspace() {
    const data = collectFormData();
    data.schema = 'odysafe.intelligence_workspace.v1';
    data.schema_version = '1.0';
    data.workspace_id = data.reference || '';
    data.exported_at = new Date().toISOString();
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    const ref = data.reference || 'intelligence-workspace';
    a.href = url;
    a.download = `${ref}_${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    showToast('JSON workspace exported');
}

function exportExcel() {
    const data = collectFormData();
    const validation = validateFlashReportData(data);
    const validationIssues = validation.errors.concat(validation.warnings);
    const incomplete = !data.subject.trim() || !data.author.trim() || validation.errors.length > 0;
    if (validationIssues.length > 0) {
        const message = formatQualityResults({errors: validation.errors.slice(0, 8), warnings: validation.warnings.slice(0, 8)}) + (validationIssues.length > 16 ? `\n\n...and ${validationIssues.length - 16} more issues.` : '') + '\n\nExport as Draft anyway?';
        if (!confirm(message)) return;
    } else if (incomplete && !confirm('This report is incomplete. Export as Draft anyway?')) return;
    if (incomplete) data.status = 'Draft';
    data.export_incomplete = incomplete;
    
    fetch('/flash-report/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(async r => {
        if (!r.ok) {
            const err = await r.json().catch(() => ({}));
            throw new Error(err.error || `Export failed (${r.status})`);
        }
        return { blob: await r.blob(), memoryStatus: r.headers.get('X-ODYSAFE-Memory-Index-Status') };
    })
    .then(({ blob, memoryStatus }) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = (data.reference || 'flash-report') + '.xlsx';
        a.click();
        window.URL.revokeObjectURL(url);
        showToast(memoryStatus === 'indexed' ? 'Report exported and indexed in CTI Memory' : 'Report exported, but Memory indexing failed');
    })
    .catch(err => {
        alert('Export failed: ' + err.message);
    });
}

// ==================== MITRE TTP SEARCH ====================

let mitreSearchTimeout = null;

function escHtml(text) {
    if (!text) return '';
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
}

function renderTtpChips(ttps) {
    const container = document.getElementById('ttps-container');
    if (!container) return;
    container.innerHTML = '';
    (ttps || []).forEach(ttp => addTtpChip(ttp.id, ttp.name, ttp.tactic));
}

function addTtpChip(id, name, tactic) {
    const container = document.getElementById('ttps-container');
    if (!container || !id) return;
    if (container.querySelector(`[data-id="${CSS.escape(id)}"]`)) return;
    const chip = document.createElement('span');
    chip.className = 'ttp-chip';
    chip.dataset.id = id;
    chip.dataset.name = name || id;
    chip.dataset.tactic = tactic || '';
    chip.innerHTML = `<strong>${escHtml(id)}</strong> ${escHtml(name || '')} <button type="button" onclick="this.closest('.ttp-chip').remove();updateFieldStatus();" aria-label="Remove">×</button>`;
    container.appendChild(chip);
    updateFieldStatus();
}

async function searchMitreTechniques(query) {
    const resultsEl = document.getElementById('mitre-search-results');
    if (!resultsEl) return;
    try {
        const response = await fetch(`/api/mitre-attack/search?q=${encodeURIComponent(query)}`);
        const data = await response.json();
        if (!data.success) {
            resultsEl.style.display = 'none';
            return;
        }
        const techniques = data.techniques || [];
        if (!techniques.length) {
            resultsEl.innerHTML = '<div style="padding:0.75rem;color:#6b7280;font-size:13px;">No techniques found</div>';
            resultsEl.style.display = 'block';
            return;
        }
        resultsEl.innerHTML = techniques.map(t => {
            const tactic = (t.tactics || []).join(', ');
            return `<button type="button" class="mitre-tech-result" data-id="${escHtml(t.id)}" data-name="${escHtml(t.name)}" data-tactic="${escHtml(tactic)}"
                style="display:block;width:100%;text-align:left;padding:0.6rem 0.75rem;background:transparent;border:none;border-bottom:1px solid rgba(109,40,217,0.15);color:#e9d5ff;cursor:pointer;font-size:13px;">
                <strong>${escHtml(t.id)}</strong> · ${escHtml(t.name)}
            </button>`;
        }).join('');
        resultsEl.querySelectorAll('.mitre-tech-result').forEach(btn => {
            btn.addEventListener('mousedown', (e) => e.preventDefault());
            btn.addEventListener('click', () => selectMitreTechnique(btn.dataset.id, btn.dataset.name, btn.dataset.tactic));
        });
        resultsEl.style.display = 'block';
    } catch (e) {
        resultsEl.style.display = 'none';
    }
}

function selectMitreTechnique(id, name, tactic) {
    addTtpChip(id, name, tactic);
    document.getElementById('mitre-search').value = '';
    document.getElementById('mitre-search-results').style.display = 'none';
}

// ==================== IOC IMPORT & SUGGESTIONS ====================

let checkedIocsToImport = [];
let reportSourceMap = new Map();
const IOC_IMPORT_PREVIEW_LIMIT = 200;
const IOC_IMPORT_BATCH_SIZE = 100;

function openImportIocsModal() {
    document.getElementById('import-iocs-modal')?.classList.add('is-open');
    loadImportSources();
}

function closeImportIocsModal() {
    document.getElementById('import-iocs-modal')?.classList.remove('is-open');
    checkedIocsToImport = [];
    const btn = document.getElementById('btn-import-checked-iocs');
    if (btn) btn.style.display = 'none';
}

async function loadImportSources() {
    const select = document.getElementById('import-source-select');
    const reportDatalist = document.getElementById('report-source-options');
    try {
        const response = await fetch('/api/sources/active');
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || 'Could not load sources');
        if (select) select.innerHTML = '<option value="">Choose a source</option>';
        if (reportDatalist) reportDatalist.innerHTML = '';
        importSourceMap = new Map();
        reportSourceMap = new Map();
        const sources = Array.isArray(data.sources) ? data.sources : (Array.isArray(data.data) ? data.data : (data.data?.sources || []));
        sources.forEach(src => {
            if (select) {
                const opt = document.createElement('option');
                opt.value = String(src.id);
                opt.textContent = src.name + (src.source_type ? ` (${src.source_type})` : '');
                select.appendChild(opt);
            }
            if (reportDatalist) {
                const opt = document.createElement('option');
                opt.value = src.name;
                opt.label = src.source_type || 'Unknown';
                reportDatalist.appendChild(opt);
            }
            importSourceMap.set(String(src.id), src);
            reportSourceMap.set(String(src.name).trim().toLowerCase(), src);
        });
        const status = document.getElementById('report-source-status');
        if (status) status.textContent = sources.length ? `${sources.length} source(s) available.` : 'No source is available in the database.';
        if (!sources.length && select) select.innerHTML = '<option value="">No source available</option>';
    } catch (e) {
        console.error('Failed to load sources:', e);
        if (select) select.innerHTML = '<option value="">Could not load sources</option>';
        const status = document.getElementById('report-source-status');
        if (status) status.textContent = 'Could not load sources from the database.';
    }
}

function addReportSourceRow(source) {
    const existing = Array.from(document.querySelectorAll('#sources-table tbody tr')).some(row => {
        const inputs = row.querySelectorAll('input');
        return inputs[0]?.value === source.name || inputs[5]?.value === String(source.id);
    });
    if (existing) return false;

    const row = document.createElement('tr');
    const created = String(source.created_at || '').slice(0, 10);
    row.innerHTML = `
        <td><input type="text" value="${escHtml(source.name || '')}"></td>
        <td><select><option>RED</option><option selected>AMBER</option><option>GREEN</option><option>CLEAR</option></select></td>
        <td><select><option>A</option><option selected>B</option><option>C</option><option>D</option><option>E</option></select></td>
        <td><select><option selected>UNKNOWN</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></td>
        <td><input type="date" value="${escHtml(created)}"></td>
        <td><input type="text" list="cti_urls_list" placeholder="Source ID / reference" value="${escHtml(String(source.id || ''))}"></td>
        <td><select><option>INTERNAL_TELEMETRY</option><option>HUMAN_REPORT</option><option>INCIDENT_RECORD</option><option>ADVISORY</option><option>VENDOR_REPORT</option><option>OSINT</option><option selected>OTHER</option></select></td>
        <td><select><option selected>Primary</option><option>Secondary</option></select></td>
        <td><select><option selected>Direct</option><option>Derived</option><option>Cited</option></select></td>
        ${FR_REMOVE_CELL}`;
    document.querySelector('#sources-table tbody').appendChild(row);
    const supportedSourceTypes = new Set(['INTERNAL_TELEMETRY', 'HUMAN_REPORT', 'INCIDENT_RECORD', 'ADVISORY', 'VENDOR_REPORT', 'OSINT', 'OTHER']);
    const sourceType = String(source.source_type || source.type || '').toUpperCase();
    row.querySelectorAll('select')[3].value = supportedSourceTypes.has(sourceType) ? sourceType : 'OTHER';
    return true;
}

async function importReportSourceWithIndicators() {
    const input = document.getElementById('report-source-search');
    const status = document.getElementById('report-source-status');
    const button = document.getElementById('report-import-source-btn');
    const container = document.getElementById('report-source-ioc-results');
    const source = reportSourceMap.get((input?.value || '').trim().toLowerCase());
    if (!source) {
        status.textContent = 'Choose an available source from the list.';
        return;
    }
    if (button) button.disabled = true;
    container.style.display = 'block';
    container.innerHTML = '<p style="text-align:center;padding:1rem;">Importing extracted indicators...</p>';
    try {
        const response = await fetch(`/api/sources/${source.id}/iocs?include_ttp=0`);
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || 'Could not load extracted indicators');
        const indicators = data.data?.iocs || data.iocs || [];
        const sourceAdded = addReportSourceRow(source);
        await appendIocsToTableInBatches(indicators, {
            statusElement: container,
            label: 'Importing extracted indicators'
        });
        input.value = '';
        status.textContent = `${source.name}: source ${sourceAdded ? 'added' : 'already present'}; ${indicators.length} extracted indicator(s) imported.`;
        container.innerHTML = `<p style="padding:1rem;">Imported ${indicators.length} extracted indicator(s) from ${escHtml(source.name || 'source')}.</p>`;
        showToast(`${indicators.length} extracted indicator(s) imported`);
    } catch (error) {
        container.innerHTML = `<p style="color:#ef4444;padding:1rem;">Could not import extracted indicators: ${escHtml(error.message)}</p>`;
        status.textContent = 'Import failed.';
    } finally {
        if (button) button.disabled = false;
    }
    updateFieldStatus();
}

async function importReportSource() {
    return importReportSourceWithIndicators();
}

async function listIocsForTypedSource() {
    const sourceId=document.getElementById('import-source-select')?.value || '';
    const container=document.getElementById('import-source-ioc-results');
    const importAllButton=document.getElementById('btn-import-source-iocs');
    checkedIocsToImport=[];
    document.getElementById('checked-iocs-count').textContent='0';
    if (importAllButton) importAllButton.disabled=!sourceId;
    if (!sourceId) { container.innerHTML='<div class="fr-search-results-empty">Choose a source to list its indicators</div>'; return; }
    container.innerHTML='<p style="text-align:center;color:#a78bfa;padding:1rem;">Loading indicators...</p>';
    try {
        const response=await fetch(`/api/sources/${encodeURIComponent(sourceId)}/iocs?include_ttp=0`); const data=await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || 'Could not load source indicators');
        const iocs=data.data?.iocs || data.iocs || [];
        renderImportIocChoices(container,iocs);
    } catch (error) { container.innerHTML='<p style="color:#ef4444;padding:1rem;">Could not load source indicators</p>'; }
}

async function importAllIocsFromSource() {
    const sourceId=document.getElementById('import-source-select')?.value || '';
    const source=importSourceMap.get(sourceId);
    if (!sourceId || !source) return;
    const button=document.getElementById('btn-import-source-iocs');
    const container=document.getElementById('import-source-ioc-results');
    button.disabled=true;
    container.innerHTML='<p style="text-align:center;color:#a78bfa;padding:1rem;">Importing indicators...</p>';
    try {
        const response=await fetch(`/api/sources/${encodeURIComponent(sourceId)}/iocs?include_ttp=0`);
        const data=await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || 'Could not load source indicators');
        const iocs=data.data?.iocs || data.iocs || [];
        await appendIocsToTableInBatches(iocs, {
            statusElement: container,
            label: `Importing indicators from ${source.name || 'source'}`
        });
        closeImportIocsModal();
        showToast(`${iocs.length} indicator(s) imported from ${source.name}`);
    } catch (error) {
        container.innerHTML='<p style="color:#ef4444;padding:1rem;">Could not import source indicators</p>';
        button.disabled=false;
    }
}

function renderImportIocChoices(container,iocs) {
    if (!iocs.length) { container.innerHTML='<p style="text-align:center;color:#6b7280;padding:1rem;">No indicators found</p>'; return; }
    const preview = iocs.slice(0, IOC_IMPORT_PREVIEW_LIMIT);
    const remaining = iocs.length - preview.length;
    container.innerHTML = `
        <div class="fr-field-hint" style="padding:0.75rem 1rem;border-bottom:1px solid rgba(109,40,217,0.15);">
            ${escHtml(String(iocs.length))} indicator(s) found. Showing ${escHtml(String(preview.length))}${remaining > 0 ? `; use "Import all from source" to import the remaining ${escHtml(String(remaining))}.` : '.'}
        </div>
        ${preview.map(ioc=>`<label style="display:flex;align-items:center;gap:8px;padding:6px;border-bottom:1px solid rgba(109,40,217,0.15);cursor:pointer;"><input type="checkbox" onchange="toggleIocImportElement(this)" data-ioc='${JSON.stringify({id:ioc.id,ioc_type:ioc.ioc_type,ioc_value:ioc.ioc_value,first_seen:ioc.first_seen,last_seen:ioc.last_seen,tlp:ioc.tlp,validation_status:ioc.validation_status,confidence:ioc.confidence,notes:ioc.notes,mitre_techniques:ioc.mitre_techniques}).replace(/'/g,"&#39;")}'><span style="font-family:monospace;font-size:12px;">${escHtml(ioc.ioc_type)}: ${escHtml(ioc.ioc_value)}</span></label>`).join('')}
    `;
    document.getElementById('btn-import-checked-iocs').style.display='inline-block';
}

function mapDbIocType(dbType) {
    const map = {
        'ipv4': 'IP', 'ipv6': 'IP', 'domain': 'Domain', 'fqdn': 'Domain',
        'url': 'URL', 'md5': 'Hash_MD5', 'sha1': 'Hash_SHA1', 'sha256': 'Hash_SHA256', 'email': 'Email'
    };
    return map[(dbType || '').toLowerCase()] || dbType || 'IP';
}

function createIocTableRow(ioc) {
    const row = document.createElement('tr');
    const iocType = mapDbIocType(ioc.type || ioc.ioc_type);
    const value = escHtml(ioc.value || ioc.ioc_value || '');
    const tlp = (ioc.tlp || 'AMBER').toUpperCase();
    const conf = ioc.confidence || (ioc.validation_status === 'TP' ? 'High' : 'Medium');
    row.dataset.iocId = ioc.id || '';
    row.innerHTML = `
        <td><select>
            <option ${iocType === 'IP' ? 'selected' : ''}>IP</option>
            <option ${iocType === 'Domain' ? 'selected' : ''}>Domain</option>
            <option ${iocType === 'URL' ? 'selected' : ''}>URL</option>
            <option ${iocType === 'Hash_MD5' ? 'selected' : ''}>Hash_MD5</option>
            <option ${iocType === 'Hash_SHA1' ? 'selected' : ''}>Hash_SHA1</option>
            <option ${iocType === 'Hash_SHA256' ? 'selected' : ''}>Hash_SHA256</option>
            <option ${iocType === 'Email' ? 'selected' : ''}>Email</option>
            <option ${iocType === 'CIDR' ? 'selected' : ''}>CIDR</option>
        </select></td>
        <td><input type="text" class="fr-cell-mono" value="${value}"></td>
        <td><select><option>Unknown</option><option>C2</option><option>Payload</option><option>Phishing</option><option>Redirector</option><option>Scanner</option><option>Staging</option><option>Malware Delivery</option><option>Victim</option></select></td>
        <td><select><option selected>UNKNOWN</option><option>ATTACKER_CONTROLLED</option><option>VICTIM_INTERNAL</option><option>BENIGN_ENVIRONMENT</option></select></td>
        <td><select>
            <option ${tlp === 'AMBER' ? 'selected' : ''}>AMBER</option>
            <option ${tlp === 'RED' ? 'selected' : ''}>RED</option>
            <option ${tlp === 'GREEN' ? 'selected' : ''}>GREEN</option>
            <option ${tlp === 'CLEAR' ? 'selected' : ''}>CLEAR</option>
        </select></td>
        <td><select>
            <option ${conf === 'High' || conf === 'high' ? 'selected' : ''}>High</option>
            <option ${conf === 'Medium' || conf === 'medium' ? 'selected' : ''}>Medium</option>
            <option ${conf === 'Low' || conf === 'low' ? 'selected' : ''}>Low</option>
        </select></td>
        <td><select><option selected>Imported</option><option>Observed</option><option>Reported</option><option>Derived</option><option>Unknown</option></select></td>
        <td><input type="date" value="${(ioc.first_seen || '').slice(0, 10)}"></td>
        <td><input type="date" value="${(ioc.last_seen || '').slice(0, 10)}"></td>
        <td><input type="date"></td>
        <td><select><option selected>UNKNOWN</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></td>
        <td><select><option selected>UNKNOWN</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></td>
        <td><select><option>Active</option><option>Inactive</option><option>Historical</option><option>Expired</option><option>Unknown</option></select></td>
        <td><select><option>Hunt</option><option>Monitor</option><option>Detect</option><option>Block Candidate</option><option selected>Enrichment Only</option><option>Do Not Block</option></select></td>
        <td><input type="date"></td>
        <td><input type="text" value="${escHtml(ioc.notes || '')}" placeholder="Context / relationship"></td>
        ${FR_REMOVE_CELL}
    `;
    return row;
}

function appendIocToTable(ioc, options = {}) {
    const tbody = document.querySelector('#iocs-table tbody');
    if (!tbody) return;
    tbody.appendChild(createIocTableRow(ioc));
    if (ioc.mitre_techniques && ioc.mitre_techniques.length) {
        ioc.mitre_techniques.forEach(function(tid) {
            if (typeof addTtpChip === 'function' && tid) {
                addTtpChip(tid, tid, '');
            }
        });
    }
    if (!options.deferStatusUpdate) updateFieldStatus();
}

function waitForNextFrame() {
    return new Promise(resolve => requestAnimationFrame(resolve));
}

async function appendIocsToTableInBatches(iocs, options = {}) {
    const tbody = document.querySelector('#iocs-table tbody');
    if (!tbody || !Array.isArray(iocs) || !iocs.length) {
        updateFieldStatus();
        return 0;
    }
    const batchSize = options.batchSize || IOC_IMPORT_BATCH_SIZE;
    const statusElement = options.statusElement || null;
    const label = options.label || 'Importing indicators';
    let imported = 0;
    for (let start = 0; start < iocs.length; start += batchSize) {
        const fragment = document.createDocumentFragment();
        const batch = iocs.slice(start, start + batchSize);
        batch.forEach(ioc => fragment.appendChild(createIocTableRow(ioc)));
        tbody.appendChild(fragment);
        imported += batch.length;
        if (statusElement) {
            statusElement.innerHTML = `<p style="text-align:center;color:#a78bfa;padding:1rem;">${escHtml(label)}... ${imported}/${iocs.length}</p>`;
        }
        await waitForNextFrame();
    }
    updateFieldStatus();
    return imported;
}

async function searchIndividualIocs() {
    const query = document.getElementById('import-ioc-search-input').value.trim();
    const container = document.getElementById('import-ioc-search-results');
    if (!query) return;
    container.innerHTML = '<p style="text-align:center;color:#a78bfa;padding:1rem;">Searching...</p>';
    try {
        const response = await fetch(`/api/iocs/load?search=${encodeURIComponent(query)}&per_page=50`);
        const data = await response.json();
        const iocs = data.iocs || data.data?.iocs || [];
        if (!iocs.length) {
            container.innerHTML = '<p style="text-align:center;color:#6b7280;padding:1rem;">No indicators found</p>';
            return;
        }
        checkedIocsToImport = [];
        container.innerHTML = iocs.map((ioc, idx) => `
            <label style="display:flex;align-items:center;gap:8px;padding:6px;border-bottom:1px solid rgba(109,40,217,0.15);cursor:pointer;">
                <input type="checkbox" onchange="toggleIocImport(${idx}, this.checked)" data-ioc='${JSON.stringify({
                    id: ioc.id,
                    ioc_type: ioc.ioc_type,
                    ioc_value: ioc.ioc_value,
                    first_seen: ioc.first_seen,
                    last_seen: ioc.last_seen,
                    tlp: ioc.tlp,
                    validation_status: ioc.validation_status,
                    confidence: ioc.confidence,
                    notes: ioc.notes,
                    mitre_techniques: ioc.mitre_techniques,
                }).replace(/'/g, "&#39;")}'>
                <span style="font-family:monospace;font-size:12px;">${ioc.ioc_type}: ${ioc.ioc_value}</span>
            </label>
        `).join('');
        document.getElementById('btn-import-checked-iocs').style.display = 'inline-block';
    } catch (e) {
        container.innerHTML = `<p style="color:#ef4444;padding:1rem;">Error: ${e.message}</p>`;
    }
}

function toggleIocImport(idx, checked) {
    const checkbox = document.querySelectorAll('#import-ioc-search-results input[type=checkbox]')[idx];
    if (!checkbox) return;
    const ioc = JSON.parse(checkbox.getAttribute('data-ioc').replace(/&#39;/g, "'"));
    if (checked) {
        checkedIocsToImport.push(ioc);
    } else {
        checkedIocsToImport = checkedIocsToImport.filter(i => i.ioc_value !== ioc.ioc_value);
    }
    document.getElementById('checked-iocs-count').textContent = checkedIocsToImport.length;
}

function toggleIocImportElement(checkbox) {
    const ioc=JSON.parse(checkbox.getAttribute('data-ioc').replace(/&#39;/g,"'"));
    if (checkbox.checked) {
        if (!checkedIocsToImport.some(item=>item.id===ioc.id)) checkedIocsToImport.push(ioc);
    } else checkedIocsToImport=checkedIocsToImport.filter(item=>item.id!==ioc.id);
    document.getElementById('checked-iocs-count').textContent=checkedIocsToImport.length;
}

async function importCheckedIocs() {
    const count = checkedIocsToImport.length;
    const container = document.getElementById('import-ioc-search-results') || document.getElementById('import-source-ioc-results');
    await appendIocsToTableInBatches(checkedIocsToImport, {
        statusElement: container,
        label: 'Importing selected indicators'
    });
    closeImportIocsModal();
    showToast(`Imported ${count} IOC(s)`);
}

// ==================== THREAT ACTOR CONTEXT HINT ====================

let mitreGroupsCache = new Map();
let threatActorHintTimeout = null;
let threatActorHintRequestId = 0;

function registerMitreGroupInCache(group) {
    if (!group || !group.id) return;
    const id = String(group.id).toUpperCase();
    mitreGroupsCache.set(id.toLowerCase(), id);
    if (group.name) {
        mitreGroupsCache.set(String(group.name).trim().toLowerCase(), id);
    }
    let aliases = group.aliases;
    if (typeof aliases === 'string' && aliases) {
        try {
            aliases = JSON.parse(aliases);
        } catch (e) {
            aliases = aliases.split(',').map(a => a.trim()).filter(Boolean);
        }
    }
    if (Array.isArray(aliases)) {
        aliases.forEach(alias => {
            if (alias) mitreGroupsCache.set(String(alias).trim().toLowerCase(), id);
        });
    }
}

async function resolveMitreGroupId(name) {
    const query = (name || '').trim();
    if (!query) return null;

    const cached = mitreGroupsCache.get(query.toLowerCase());
    if (cached) return cached;

    try {
        const response = await fetch('/api/mitre-attack/groups?search=' + encodeURIComponent(query));
        const data = await response.json();
        if (!data.success) return null;

        const groups = data.groups || [];
        const lower = query.toLowerCase();
        const match = groups.find(g => g.id && g.id.toLowerCase() === lower)
            || groups.find(g => g.name && g.name.toLowerCase() === lower)
            || groups.find(g => (g.aliases || []).some(a => a && a.toLowerCase() === lower))
            || groups[0];

        if (match && match.id) {
            registerMitreGroupInCache(match);
            return String(match.id).toUpperCase();
        }
    } catch (e) {
        console.warn('Failed to resolve MITRE group:', e);
    }
    return null;
}

function setThreatActorHint(text, visible) {
    const hintEl = document.getElementById('threat-actor-hint');
    if (!hintEl) return;
    if (!visible || !text) {
        hintEl.textContent = '';
        hintEl.hidden = true;
        return;
    }
    hintEl.textContent = text;
    hintEl.hidden = false;
}

async function updateThreatActorHint() {
    const input = document.getElementById('threat_actor');
    if (!input) return;

    const value = input.value.trim();
    if (value.length < 2) {
        setThreatActorHint('', false);
        return;
    }

    const requestId = ++threatActorHintRequestId;
    const groupId = await resolveMitreGroupId(value);
    if (requestId !== threatActorHintRequestId) return;

    if (!groupId) {
        setThreatActorHint('', false);
        return;
    }

    try {
        const [techResp, overlapResp] = await Promise.all([
            fetch('/api/mitre-attack/groups/' + encodeURIComponent(groupId) + '/techniques'),
            fetch('/api/mitre-attack/groups/' + encodeURIComponent(groupId) + '/ioc-overlap'),
        ]);
        if (requestId !== threatActorHintRequestId) return;

        const techData = await techResp.json();
        if (!techData.success) {
            setThreatActorHint('', false);
            return;
        }

        let overlapData = null;
        if (overlapResp.ok) {
            overlapData = await overlapResp.json();
        }

        const group = techData.group || {};
        const techniques = techData.techniques || [];
        const total = techData.count != null ? techData.count : techniques.length;
        const sample = techniques.slice(0, 4).map(t => {
            if (t.name) return t.id + ' ' + t.name;
            return t.id;
        });

        const groupLabel = group.name ? group.id + ' · ' + group.name : groupId;
        let message = 'MITRE ATT&CK ' + groupLabel + ': ' + total + ' technique' + (total !== 1 ? 's' : '') + '.';
        if (sample.length) {
            message += ' Examples: ' + sample.join('; ');
            if (total > sample.length) message += '…';
        }

        if (overlapData && overlapData.success && overlapData.matched_count > 0) {
            const matched = overlapData.matched_count;
            message += ' ' + matched + ' technique' + (matched !== 1 ? 's' : '') + ' match TTP indicators in your workspace.';
        }

        setThreatActorHint(message, true);
    } catch (e) {
        console.warn('Failed to load threat actor hint:', e);
        setThreatActorHint('', false);
    }
}

function scheduleThreatActorHint() {
    clearTimeout(threatActorHintTimeout);
    threatActorHintTimeout = setTimeout(updateThreatActorHint, 400);
}

async function loadFlashReportSuggestions() {
    try {
        const groupsResp = await fetch('/api/mitre/groups');
        const groupsData = await groupsResp.json();
        const groupsList = document.getElementById('mitre_groups_list');
        if (groupsList && groupsData.success) {
            groupsList.innerHTML = '';
            (groupsData.groups || groupsData.data?.groups || []).forEach(g => {
                registerMitreGroupInCache(g);
                const opt = document.createElement('option');
                opt.value = g.name || g.id;
                groupsList.appendChild(opt);
            });
        }
        const urlsResp = await fetch('/api/cti-resources/urls');
        const urlsData = await urlsResp.json();
        const urlsList = document.getElementById('cti_urls_list');
        if (urlsList && urlsData.success) {
            urlsList.innerHTML = '';
            (urlsData.urls || urlsData.data?.urls || []).slice(0, 500).forEach(u => {
                const opt = document.createElement('option');
                opt.value = u.url;
                opt.label = u.name || u.url;
                urlsList.appendChild(opt);
            });
        }
    } catch (e) {
        console.error('Failed to load suggestions:', e);
    }
}

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('#block-8 .rule-container .btn-remove').forEach(button => {
        button.addEventListener('click', function() {
            this.closest('.rule-container')?.remove();
            updateFieldStatus();
        });
    });
    // Generate initial reference
    const now = new Date();
    document.getElementById('reference').value = generateUniqueReference();
    
    const isoString = now.toISOString().slice(0, 16);
    document.getElementById('created_at').value = isoString;
    document.getElementById('updated_at').value = isoString;
    
    // Initialize saved reports panel
    renderSavedReportsList();
    loadServerReports();
    
    loadFlashReportSuggestions();

    const params = new URLSearchParams(window.location.search);
    const prefillIoc = params.get('prefill_ioc');
    if (prefillIoc) {
        fetch('/api/ioc/' + encodeURIComponent(prefillIoc) + '/correlations')
            .then(function(r) { return r.json(); })
            .then(function(resp) {
                if (!resp.success || !resp.ioc) return;
                const ioc = resp.ioc;
                appendIocToTable({
                    id: ioc.id,
                    ioc_type: ioc.ioc_type,
                    ioc_value: ioc.ioc_value,
                    first_seen: ioc.first_seen,
                    last_seen: ioc.last_seen,
                    tlp: ioc.tlp,
                    validation_status: ioc.validation_status,
                    confidence: ioc.confidence,
                    notes: ioc.notes,
                    mitre_techniques: (resp.mitre_links || []).map(function(l) { return l.technique_id; }),
                });
                showBlock(7);
                showToast('Indicator imported into the workspace');
            })
            .catch(function(error) { console.error('IOC prefill failed:', error); showStorageWarning('The requested IOC could not be imported.'); });
    }

    const threatActorInput = document.getElementById('threat_actor');
    if (threatActorInput) {
        threatActorInput.addEventListener('input', scheduleThreatActorHint);
        threatActorInput.addEventListener('change', scheduleThreatActorHint);
    }

    const mitreSearchInput = document.getElementById('mitre-search');
    if (mitreSearchInput) {
        mitreSearchInput.addEventListener('input', function() {
            clearTimeout(mitreSearchTimeout);
            const q = this.value.trim();
            if (q.length < 2) {
                document.getElementById('mitre-search-results').style.display = 'none';
                return;
            }
            mitreSearchTimeout = setTimeout(() => searchMitreTechniques(q), 300);
        });
        mitreSearchInput.addEventListener('blur', function() {
            setTimeout(() => {
                const resultsEl = document.getElementById('mitre-search-results');
                if (resultsEl) resultsEl.style.display = 'none';
            }, 200);
        });
    }
    const importSourceSelect=document.getElementById('import-source-select');
    if (importSourceSelect) importSourceSelect.addEventListener('change',listIocsForTypedSource);
    loadImportSources();
    initAnalystProgressInteractions();
    
    // Initialize status
    showBlock(1);
    updateFieldStatus();
    updateToolbarMeta();
    
    // Add input listeners for auto-update
    document.querySelectorAll('input, textarea, select').forEach(el => {
        el.addEventListener('change', updateFieldStatus);
        el.addEventListener('input', updateFieldStatus);
    });
    
    // Draft banner (no blocking popup)
    const draft = localStorage.getItem(DRAFT_STORAGE_KEY);
    if (draft) {
        try {
            const parsed = JSON.parse(draft);
            if (parsed.reference || parsed.subject || parsed.author) {
                showDraftBanner();
            }
        } catch (e) {
            localStorage.removeItem(DRAFT_STORAGE_KEY);
        }
    }
});

// Auto-save draft every 30 seconds
setInterval(() => {
    const data = collectFormData();
    if (data.author || data.subject) {
        localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(data));
    }
}, 30000);
