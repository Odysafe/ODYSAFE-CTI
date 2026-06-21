const DRAFT_STORAGE_KEY = 'flint_draft';
const TOTAL_SECTIONS = 13;
let currentBlock = 1;

const FR_REMOVE_CELL = '<td class="fr-table-actions"><button type="button" class="btn-remove" onclick="this.closest(\'tr\').remove(); updateFieldStatus();" aria-label="Remove row">×</button></td>';

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
        <button type="button" class="btn-remove" onclick="this.parentElement.remove(); updateFieldStatus();" aria-label="Remove takeaway">×</button>
    `;
    container.appendChild(row);
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
        <td>
            <select>
                <option>Critical</option>
                <option>High</option>
                <option>Medium</option>
                <option>Low</option>
            </select>
        </td>
        <td><input type="text" placeholder="Source"></td>
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
        <td><input type="date"></td>
        <td><input type="date"></td>
        <td><input type="date"></td>
        <td><input type="checkbox" checked></td>
        ${FR_REMOVE_CELL}
    `;
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
            </select>
            <button type="button" class="btn-remove" onclick="this.closest('.rule-container').remove(); updateFieldStatus();" aria-label="Remove rule">×</button>
        </div>
        <textarea placeholder="Enter detection rule here..."></textarea>
    `;
    container.insertBefore(ruleDiv, container.lastElementChild);
    updateFieldStatus();
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
            </select>
        </td>
        <td><input type="text" placeholder="Team/Person"></td>
        <td><input type="date"></td>
        <td>
            <select>
                <option>Todo</option>
                <option>In Progress</option>
                <option>Done</option>
            </select>
        </td>
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
        <td><input type="date"></td>
        <td><input type="text" list="cti_urls_list" placeholder="https://..."></td>
        <td>
            <select>
                <option>Advisory</option>
                <option>Blog</option>
                <option>CERT</option>
                <option>Vendor</option>
                <option>OSINT</option>
                <option>Private</option>
            </select>
        </td>
        ${FR_REMOVE_CELL}
    `;
    tbody.appendChild(row);
    updateFieldStatus();
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

// Save Report (permanent)
function saveReport() {
    const reportData = collectFormData();
    
    if (!reportData.reference) {
        alert('Please generate a reference number first');
        return;
    }
    
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

// Load specific report
function loadReport(reportId) {
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
    
    const reports = getSavedReports().filter(r => r.id !== reportId);
    localStorage.setItem(REPORTS_STORAGE_KEY, JSON.stringify(reports));
    
    if (currentReportId === reportId) {
        currentReportId = null;
    }
    
    renderSavedReportsList();
}

// Create new report (clear form)
function createNewReport() {
    if (currentReportId || document.getElementById('subject')?.value?.trim()) {
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
    
    // Clear takeaways
    const takeawayContainer = document.getElementById('takeaways-container');
    takeawayContainer.innerHTML = `
        <div class="takeaway-row" style="display: flex; gap: 0.5rem; margin-bottom: 0.5rem;">
            <input type="text" class="takeaway-input" style="flex: 1; padding: 0.75rem; background: rgba(30,20,50,0.8); border: 1px solid rgba(109,40,217,0.3); border-radius: 8px; color: #e9d5ff;" placeholder="Key point for decision makers">
            <button type="button" class="btn-remove" onclick="this.parentElement.remove();">×</button>
        </div>
    `;
    
    // Reset dates and reference
    const now = new Date();
    const year = now.getUTCFullYear();
    const random = Math.floor(Math.random() * 900) + 100;
    document.getElementById('reference').value = `FLINT-${year}-${random}`;
    const isoString = now.toISOString().slice(0, 16);
    document.getElementById('created_at').value = isoString;
    document.getElementById('updated_at').value = isoString;
    
    updateFieldStatus();
    showBlock(1);
    updateToolbarMeta();
    showToast('New report started');
}

// Render saved reports list
function renderSavedReportsList() {
    const container = document.getElementById('reports-list');
    if (!container) return;
    const reports = getSavedReports();
    
    if (reports.length === 0) {
        container.innerHTML = '<div class="reports-empty">No saved reports yet.</div>';
        return;
    }
    
    reports.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    
    container.innerHTML = reports.map(report => {
        const isActive = report.id === currentReportId;
        const createdDate = new Date(report.createdAt).toLocaleDateString();
        const safeId = report.id.replace(/'/g, "\\'");
        return `
            <div class="report-item ${isActive ? 'active' : ''}" onclick="loadReport('${safeId}')">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
                    <div style="min-width:0;flex:1;">
                        <div class="report-item-ref">${escHtml(report.reference || 'No reference')}</div>
                        <div class="report-item-meta">${escHtml(report.subject || 'No subject')} · ${createdDate}</div>
                        <div class="report-item-tags">
                            <span class="report-tag">${escHtml(report.tlp || 'AMBER')}</span>
                            <span class="report-tag">${escHtml(report.priority || 'Medium')}</span>
                        </div>
                    </div>
                    <button type="button" class="btn-remove" onclick="deleteReport('${safeId}', event)" title="Delete">×</button>
                </div>
            </div>
        `;
    }).join('');
}

function toggleSavedReportsPanel() {
    openHistoryDrawer();
}

// Helper: Get TLP color
function getTlpColor(tlp) {
    const colors = {
        'RED': '#dc3545',
        'AMBER': '#ffc107',
        'AMBER+STRICT': '#ff8c00',
        'GREEN': '#28a745',
        'CLEAR': '#17a2b8'
    };
    return colors[tlp] || '#ffc107';
}

// Helper: Get priority color
function getPriorityColor(priority) {
    const colors = {
        'Critical': '#7f1d1d',
        'High': '#dc2626',
        'Medium': '#f59e0b',
        'Low': '#6b7280'
    };
    return colors[priority] || '#6b7280';
}

// Collect all form data
function collectFormData() {
    const data = {
        // Basic fields
        reference: document.getElementById('reference')?.value || '',
        created_at: document.getElementById('created_at')?.value || '',
        updated_at: new Date().toISOString().slice(0, 16),
        author: document.getElementById('author')?.value || '',
        subject: document.getElementById('subject')?.value || '',
        
        // Selected badges
        tlp: document.querySelector('#tlp-selector .badge-option.selected')?.dataset.value || 'RED',
        pap: document.querySelector('#pap-selector .badge-option.selected')?.dataset.value || 'AMBER',
        priority: document.querySelector('#priority-selector .badge-option.selected')?.dataset.value || 'Medium',
        status: document.querySelector('#status-selector .badge-option.selected')?.dataset.value || 'Draft',
        incident_confidence: document.querySelector('#incident-confidence-selector .badge-option.selected')?.dataset.value || 'Likely',
        overall_confidence: document.querySelector('#confidence-selector .badge-option.selected')?.dataset.value || 'Likely',
        cves: document.getElementById('cves')?.value || '',
        incident_type: document.getElementById('incident_type')?.value || '',
        threat_actor: document.getElementById('threat_actor')?.value || '',
        affected_entities: document.getElementById('affected_entities')?.value || '',
        threat_nature: document.getElementById('threat_nature')?.value || '',
        urgency_action: document.getElementById('urgency_action')?.value || '',
        impact_confidentiality: document.getElementById('impact_confidentiality')?.value || '',
        impact_integrity: document.getElementById('impact_integrity')?.value || '',
        impact_availability: document.getElementById('impact_availability')?.value || '',
        
        // Takeaways
        takeaways: Array.from(document.querySelectorAll('.takeaway-input')).map(i => i.value).filter(v => v),
        
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

        // Distribution metadata
        feedback_contact: document.getElementById('feedback_contact')?.value || '',
        distribution_handling: document.getElementById('distribution_handling')?.value || '',
        disclaimer: document.getElementById('disclaimer')?.value || '',

        // Tables
        iocs: [],
        detection_rules: [],
        recommendations: [],
        timeline: [],
        sources: [],
        recipients: [],
        ttps: [],
        
        // Defang option
        defang_export: document.getElementById('defang_export')?.checked || false
    };
    
    // Collect IOCs
    document.querySelectorAll('#iocs-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input, select');
        if (inputs.length >= 8) {
            data.iocs.push({
                type: inputs[0]?.value || '',
                value: inputs[1]?.value || '',
                tlp: inputs[2]?.value || '',
                confidence: inputs[3]?.value || '',
                first_seen: inputs[4]?.value || '',
                last_seen: inputs[5]?.value || '',
                expiration: inputs[6]?.value || '',
                active: inputs[7]?.checked || false
            });
        }
    });

    // Collect timeline
    document.querySelectorAll('#timeline-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input, select');
        if (inputs.length >= 4) {
            data.timeline.push({
                date: inputs[0]?.value || '',
                event: inputs[1]?.value || '',
                impact: inputs[2]?.value || 'Medium',
                source: inputs[3]?.value || ''
            });
        }
    });

    // Collect sources
    document.querySelectorAll('#sources-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input, select');
        if (inputs.length >= 6) {
            data.sources.push({
                name: inputs[0]?.value || '',
                tlp: inputs[1]?.value || 'AMBER',
                reliability: inputs[2]?.value || 'A',
                date: inputs[3]?.value || '',
                url: inputs[4]?.value || '',
                type: inputs[5]?.value || 'Advisory'
            });
        }
    });

    // Collect recipients
    document.querySelectorAll('#recipients-table tbody tr').forEach(row => {
        const inputs = row.querySelectorAll('input');
        if (inputs.length >= 4) {
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
                content: textarea.value
            });
        }
    });
    
    // Collect recommendations
    document.querySelectorAll('#block-9 table tbody tr').forEach(row => {
        const selects = row.querySelectorAll('select');
        const inputs = row.querySelectorAll('input');
        if (selects.length >= 3 && inputs.length >= 2) {
            data.recommendations.push({
                priority: selects[0]?.value || '',
                action: inputs[0]?.value || '',
                type: selects[1]?.value || '',
                owner: inputs[1]?.value || '',
                due_date: inputs[2]?.value || '',
                status: selects[2]?.value || 'Todo'
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
    
    return data;
}

// Populate form with saved data
function populateFormData(data) {
    // Set basic fields
    if (data.reference) document.getElementById('reference').value = data.reference;
    if (data.created_at) document.getElementById('created_at').value = data.created_at;
    if (data.author) document.getElementById('author').value = data.author;
    if (data.subject) document.getElementById('subject').value = data.subject;
    if (data.threat_actor) {
        document.getElementById('threat_actor').value = data.threat_actor;
        scheduleThreatActorHint();
    }
    if (data.cves) document.getElementById('cves').value = data.cves;
    if (data.incident_confidence) {
        document.querySelectorAll('#incident-confidence-selector .badge-option').forEach(b => b.classList.remove('selected'));
        const incBadge = document.querySelector(`#incident-confidence-selector .badge-option[data-value="${data.incident_confidence}"]`);
        if (incBadge) incBadge.classList.add('selected');
    }
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
    if (data.source_reliability) document.getElementById('source_reliability').value = data.source_reliability;
    if (data.biases) document.getElementById('biases').value = data.biases;
    if (data.section_confidence) document.getElementById('section_confidence').value = data.section_confidence;

    // Block 13 distribution metadata
    if (data.feedback_contact) document.getElementById('feedback_contact').value = data.feedback_contact;
    if (data.distribution_handling) document.getElementById('distribution_handling').value = data.distribution_handling;
    if (data.disclaimer) document.getElementById('disclaimer').value = data.disclaimer;

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
    if (data.overall_confidence || data.confidence) {
        document.querySelectorAll('#confidence-selector .badge-option').forEach(b => b.classList.remove('selected'));
        const confBadge = document.querySelector(`#confidence-selector .badge-option[data-value="${data.overall_confidence || data.confidence}"]`);
        if (confBadge) confBadge.classList.add('selected');
    }
    
    // Set takeaways
    if (data.takeaways && data.takeaways.length > 0) {
        const container = document.getElementById('takeaways-container');
        container.innerHTML = '';
        data.takeaways.forEach(text => {
            const row = document.createElement('div');
            row.className = 'takeaway-row';
            row.innerHTML = `
                <input type="text" class="takeaway-input" value="${text.replace(/"/g, '&quot;')}">
                <button type="button" class="btn-remove" onclick="this.parentElement.remove(); updateFieldStatus();" aria-label="Remove takeaway">×</button>
            `;
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
                        <option ${event.impact === 'Critical' ? 'selected' : ''}>Critical</option>
                        <option ${event.impact === 'High' ? 'selected' : ''}>High</option>
                        <option ${event.impact === 'Medium' ? 'selected' : ''}>Medium</option>
                        <option ${event.impact === 'Low' ? 'selected' : ''}>Low</option>
                    </select>
                </td>
                <td><input type="text" placeholder="Source" value="${(event.source || '').replace(/"/g, '&quot;')}"></td>
                ${FR_REMOVE_CELL}
            `;
            tbody.appendChild(row);
        });
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
                <td><input type="date" value="${src.date || ''}"></td>
                <td><input type="text" list="cti_urls_list" placeholder="https://..." value="${(src.url || '').replace(/"/g, '&quot;')}"></td>
                <td>
                    <select>
                        <option ${src.type === 'Advisory' ? 'selected' : ''}>Advisory</option>
                        <option ${src.type === 'Blog' ? 'selected' : ''}>Blog</option>
                        <option ${src.type === 'CERT' ? 'selected' : ''}>CERT</option>
                        <option ${src.type === 'Vendor' ? 'selected' : ''}>Vendor</option>
                        <option ${src.type === 'OSINT' ? 'selected' : ''}>OSINT</option>
                        <option ${src.type === 'Private' ? 'selected' : ''}>Private</option>
                    </select>
                </td>
                ${FR_REMOVE_CELL}
            `;
            tbody.appendChild(row);
        });
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
                <td><input type="date" value="${ioc.first_seen || ''}"></td>
                <td><input type="date" value="${ioc.last_seen || ''}"></td>
                <td><input type="date" value="${ioc.expiration || ''}"></td>
                <td><input type="checkbox" ${ioc.active ? 'checked' : ''}></td>
                ${FR_REMOVE_CELL}
            `;
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
                    </select>
                    <button type="button" class="btn-remove" onclick="this.closest('.rule-container').remove(); updateFieldStatus();">×</button>
                </div>
                <textarea style="width: 100%; min-height: 120px; font-family: monospace; font-size: 0.85rem; background: rgba(20,15,35,0.9); color: #e9d5ff; padding: 1rem; border: 1px solid rgba(109,40,217,0.3); border-radius: 6px;" placeholder="Enter detection rule here...">${rule.content || ''}</textarea>
            `;
            container.insertBefore(ruleDiv, container.lastElementChild);
        });
    }

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
                        <option ${rec.status === 'Done' ? 'selected' : ''}>Done</option>
                    </select>
                </td>
                ${FR_REMOVE_CELL}
            `;
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
    
    sections.forEach((section, index) => {
        const status = checkSectionStatus(section);
        const step = document.querySelector('.wizard-step[data-step="' + (index + 1) + '"]');
        
        if (step) {
            step.classList.remove('completed', 'partial', 'empty');
            if (status === 'complete') {
                step.classList.add('completed');
                filled++;
            } else if (status === 'partial') {
                step.classList.add('partial');
                filled += 0.5;
            }
        }
    });
    
    const percent = Math.round((filled / sections.length) * 100);
    const fill = document.getElementById('fr-progress-fill');
    const label = document.getElementById('fr-progress-percent');
    if (fill) fill.style.width = percent + '%';
    if (label) label.textContent = percent + '%';
}

const SECTION_RULES = {
    'block-1': () => !!document.getElementById('author')?.value?.trim(),
    'block-2': () => !!document.getElementById('subject')?.value?.trim() && !!document.getElementById('incident_type')?.value,
    'block-3': () => {
        const fields = ['affected_entities', 'threat_nature', 'urgency_action'];
        return fields.some(id => document.getElementById(id)?.value?.trim());
    },
    'block-4': () => Array.from(document.querySelectorAll('.takeaway-input')).some(i => i.value.trim()),
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
    'block-8': () => document.querySelectorAll('#block-8 .rule-container textarea').length > 0 &&
        Array.from(document.querySelectorAll('#block-8 .rule-container textarea')).some(t => t.value.trim()),
    'block-9': () => Array.from(document.querySelectorAll('#block-9 tbody tr')).some(row => {
        const action = row.querySelector('td:nth-child(2) input');
        return action && action.value.trim();
    }),
    'block-10': () => ['known_unknowns', 'hunt_questions', 'rfis'].some(id => document.getElementById(id)?.value?.trim()),
    'block-11': () => ['source_reliability', 'biases', 'section_confidence'].some(id => document.getElementById(id)?.value?.trim()) ||
        document.querySelector('#confidence-selector .badge-option.selected'),
    'block-12': () => Array.from(document.querySelectorAll('#sources-table tbody tr')).some(row => {
        const name = row.querySelector('input');
        return name && name.value.trim();
    }),
    'block-13': () => {
        const hasRecipient = Array.from(document.querySelectorAll('#recipients-table tbody tr')).some(row => {
            const name = row.querySelector('input');
            return name && name.value.trim();
        });
        const fields = ['feedback_contact', 'distribution_handling', 'disclaimer'];
        return hasRecipient || fields.some(id => document.getElementById(id)?.value?.trim());
    }
};

const OPTIONAL_SECTIONS = new Set(['block-8', 'block-10', 'block-11']);

// Check section status
function checkSectionStatus(section) {
    const rule = SECTION_RULES[section.id];
    if (!rule) return 'empty';
    if (rule()) return 'complete';
    if (OPTIONAL_SECTIONS.has(section.id)) return 'complete';
    const hasAny = Array.from(section.querySelectorAll('input:not([readonly]), textarea, select')).some(el => {
        if (el.type === 'checkbox') return el.checked;
        return el.value && String(el.value).trim();
    });
    return hasAny ? 'partial' : 'empty';
}

// Update field status
function updateFieldStatus() {
    document.querySelectorAll('.flash-section').forEach(section => {
        const statusEl = section.querySelector('.section-status');
        if (statusEl) {
            const status = checkSectionStatus(section);
            statusEl.className = 'section-status status-' + status;
            statusEl.textContent = status === 'complete' ? 'Complete' : status === 'partial' ? 'Partial' : 'Incomplete';
        }
    });
    updateProgressIndicator();
    updateToolbarMeta();
}

// ==================== EXPORT FUNCTIONS ====================

function exportExcel() {
    const data = collectFormData();
    
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
        return r.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = (data.reference || 'flash-report') + '.xlsx';
        a.click();
        window.URL.revokeObjectURL(url);
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
    try {
        const response = await fetch('/api/sources/active');
        const data = await response.json();
        select.innerHTML = '<option value="">-- Choose a Source --</option>';
        if (data.success) {
            (data.sources || data.data?.sources || []).forEach(src => {
                const opt = document.createElement('option');
                opt.value = src.id;
                opt.textContent = `${src.name} (${src.source_type || 'unknown'})`;
                select.appendChild(opt);
            });
        }
    } catch (e) {
        console.error('Failed to load sources:', e);
    }
}

function mapDbIocType(dbType) {
    const map = {
        'ipv4': 'IP', 'ipv6': 'IP', 'domain': 'Domain', 'fqdn': 'Domain',
        'url': 'URL', 'md5': 'Hash_MD5', 'sha1': 'Hash_SHA1', 'sha256': 'Hash_SHA256', 'email': 'Email'
    };
    return map[(dbType || '').toLowerCase()] || dbType || 'IP';
}

function appendIocToTable(ioc) {
    const tbody = document.querySelector('#iocs-table tbody');
    const row = document.createElement('tr');
    const iocType = mapDbIocType(ioc.type || ioc.ioc_type);
    const value = (ioc.value || ioc.ioc_value || '').replace(/"/g, '&quot;');
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
        <td><select><option>AMBER</option><option>RED</option><option>GREEN</option></select></td>
        <td><select><option>High</option><option>Medium</option><option>Low</option></select></td>
        <td><input type="date" value="${ioc.first_seen || ''}"></td>
        <td><input type="date" value="${ioc.last_seen || ''}"></td>
        <td><input type="date"></td>
        <td><input type="checkbox" checked></td>
        ${FR_REMOVE_CELL}
    `;
    tbody.appendChild(row);
    updateFieldStatus();
}

async function importIocsFromSelectedSource() {
    const sourceId = document.getElementById('import-source-select').value;
    if (!sourceId) {
        alert('Please select a source');
        return;
    }
    try {
        const response = await fetch(`/api/sources/${sourceId}/iocs`);
        const data = await response.json();
        const iocs = data.data?.iocs || data.iocs || [];
        if (!iocs.length) {
            alert('No IOCs found for this source');
            return;
        }
        iocs.forEach(ioc => appendIocToTable({
            ioc_type: ioc.ioc_type,
            ioc_value: ioc.ioc_value,
            first_seen: ioc.first_seen,
            last_seen: ioc.last_seen
        }));
        closeImportIocsModal();
        alert(`Imported ${iocs.length} IOC(s)`);
    } catch (e) {
        alert('Import failed: ' + e.message);
    }
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
            container.innerHTML = '<p style="text-align:center;color:#6b7280;padding:1rem;">No IOCs found</p>';
            return;
        }
        checkedIocsToImport = [];
        container.innerHTML = iocs.map((ioc, idx) => `
            <label style="display:flex;align-items:center;gap:8px;padding:6px;border-bottom:1px solid rgba(109,40,217,0.15);cursor:pointer;">
                <input type="checkbox" onchange="toggleIocImport(${idx}, this.checked)" data-ioc='${JSON.stringify({ioc_type: ioc.ioc_type, ioc_value: ioc.ioc_value, first_seen: ioc.first_seen, last_seen: ioc.last_seen}).replace(/'/g, "&#39;")}'>
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

function importCheckedIocs() {
    checkedIocsToImport.forEach(ioc => appendIocToTable(ioc));
    closeImportIocsModal();
    alert(`Imported ${checkedIocsToImport.length} IOC(s)`);
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
            message += ' ' + matched + ' technique' + (matched !== 1 ? 's' : '') + ' match TTP IOCs in your workspace.';
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
    // Generate initial reference
    const now = new Date();
    const year = now.getUTCFullYear();
    const random = Math.floor(Math.random() * 900) + 100;
    document.getElementById('reference').value = `FLINT-${year}-${random}`;
    
    const isoString = now.toISOString().slice(0, 16);
    document.getElementById('created_at').value = isoString;
    document.getElementById('updated_at').value = isoString;
    
    // Initialize saved reports panel
    renderSavedReportsList();
    
    loadFlashReportSuggestions();

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
