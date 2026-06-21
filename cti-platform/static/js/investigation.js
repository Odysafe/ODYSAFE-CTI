(function () {
    'use strict';

    const boot = window.INVESTIGATION_BOOT || {};
    let currentGroupId = boot.groupId;

    const tabs = document.querySelectorAll('.inv-tab');
    const panels = document.querySelectorAll('.inv-panel');

    tabs.forEach(function (tab) {
        tab.addEventListener('click', function () {
            const name = tab.getAttribute('data-tab');
            tabs.forEach(function (t) { t.classList.toggle('is-active', t === tab); });
            panels.forEach(function (p) {
                const active = p.id === 'tab-' + name;
                p.classList.toggle('is-active', active);
                p.hidden = !active;
            });
            if (name === 'deliverables') loadDeliverables();
            if (name === 'ttp') loadTtpCoverage();
        });
    });

    function escapeHtml(text) {
        if (text == null) return '';
        const d = document.createElement('div');
        d.textContent = String(text);
        return d.innerHTML;
    }

    function updateScopedLinks(groupId) {
        const iocsLink = document.getElementById('link-iocs-scoped');
        if (iocsLink) {
            iocsLink.href = groupId ? '/iocs?group=' + encodeURIComponent(groupId) : '/iocs';
        }
    }

    function renderStats(stats) {
        const el = document.getElementById('session-stats');
        if (!el || !stats) return;
        el.innerHTML =
            statBlock(stats.ioc_count, 'IOCs in scope') +
            statBlock(stats.true_positive_count, 'True positives') +
            statBlock(stats.ttp_link_count, 'Linked TTPs') +
            statBlock(stats.log_incident_count, 'Log analyses');
    }

    function statBlock(value, label) {
        return '<div class="inv-stat"><span class="inv-stat-value">' + (value || 0) +
            '</span><span class="inv-stat-label">' + escapeHtml(label) + '</span></div>';
    }

    function showFeedback(msg, type) {
        const el = document.getElementById('session-feedback');
        if (!el) return;
        el.textContent = msg;
        el.className = 'inv-feedback ' + (type || '');
    }

    document.getElementById('session-form')?.addEventListener('submit', async function (e) {
        e.preventDefault();
        const name = document.getElementById('session-name').value.trim();
        const notes = document.getElementById('session-notes').value.trim();
        const groupVal = document.getElementById('session-group').value;
        const idVal = document.getElementById('session-id').value;

        const payload = {
            name: name,
            notes: notes,
            group_id: groupVal || null,
        };
        if (idVal) payload.id = parseInt(idVal, 10);

        try {
            const r = await fetch('/investigation/api/session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await r.json();
            if (!r.ok || !data.success) {
                showFeedback(data.error || 'Save failed', 'error');
                return;
            }
            if (data.session) {
                document.getElementById('session-id').value = data.session.id || '';
                currentGroupId = data.session.group_id || null;
                updateScopedLinks(currentGroupId);
            }
            if (data.stats) renderStats(data.stats);
            showFeedback('Session saved.', 'success');

            const closeBtn = document.getElementById('btn-close-session');
            if (!closeBtn && data.session) {
                const actions = document.querySelector('.inv-form-actions');
                if (actions) {
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.id = 'btn-close-session';
                    btn.className = 'btn btn-secondary';
                    btn.textContent = 'Close session';
                    btn.addEventListener('click', closeSession);
                    actions.appendChild(btn);
                }
            }
        } catch (err) {
            showFeedback('Error: ' + err.message, 'error');
        }
    });

    async function closeSession() {
        if (!confirm('Close this investigation session?')) return;
        const idVal = document.getElementById('session-id').value;
        try {
            const r = await fetch('/investigation/api/session/close', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: idVal ? parseInt(idVal, 10) : null }),
            });
            const data = await r.json();
            if (!r.ok) {
                showFeedback(data.error || 'Close failed', 'error');
                return;
            }
            document.getElementById('session-id').value = '';
            document.getElementById('session-name').value = '';
            document.getElementById('session-notes').value = '';
            document.getElementById('session-group').value = '';
            document.getElementById('btn-close-session')?.remove();
            currentGroupId = null;
            updateScopedLinks(null);
            showFeedback('Session closed.', 'success');
            await refreshSessionStats();
        } catch (err) {
            showFeedback('Error: ' + err.message, 'error');
        }
    }

    document.getElementById('btn-close-session')?.addEventListener('click', closeSession);

    document.getElementById('session-group')?.addEventListener('change', function () {
        currentGroupId = this.value ? parseInt(this.value, 10) : null;
        updateScopedLinks(currentGroupId);
    });

    async function loadDeliverables() {
        const container = document.getElementById('deliverables-content');
        if (!container) return;
        container.innerHTML = '<div class="inv-empty">Loading...</div>';
        try {
            const r = await fetch('/investigation/api/deliverables?limit=50');
            const data = await r.json();
            const outputs = data.outputs || [];
            if (!outputs.length) {
                container.innerHTML = '<div class="inv-empty">No files in outputs/ yet. Export IOCs or save reports to see them here.</div>';
                return;
            }
            const folderLabels = { iocs: 'IOCs', stix: 'STIX', reports: 'Reports' };
            let html = '<div class="inv-table-wrap"><table class="inv-table"><thead><tr>' +
                '<th>Name</th><th>Type</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>';
            outputs.forEach(function (o) {
                const rel = o.path.replace(/^.*outputs[/\\]/, '');
                html += '<tr><td>' + escapeHtml(o.name) + '</td><td><span class="inv-badge">' +
                    escapeHtml(folderLabels[o.folder] || o.folder) + '</span></td><td>' +
                    escapeHtml(o.size_formatted || '-') + '</td><td>' +
                    escapeHtml(new Date(o.modified).toLocaleString()) + '</td><td>' +
                    '<a href="/api/settings/outputs/' + encodeURIComponent(rel) + '/download" class="btn btn-secondary btn-sm">Download</a></td></tr>';
            });
            html += '</tbody></table></div>';
            container.innerHTML = html;
        } catch (err) {
            container.innerHTML = '<div class="inv-empty">Error loading deliverables.</div>';
        }
    }

    async function loadTtpCoverage() {
        const iocsEl = document.getElementById('ttp-iocs-content');
        const logsEl = document.getElementById('ttp-logs-content');
        if (!iocsEl || !logsEl) return;

        iocsEl.innerHTML = '<div class="inv-empty">Loading...</div>';
        logsEl.innerHTML = '<div class="inv-empty">Loading...</div>';

        const q = currentGroupId ? '?group_id=' + encodeURIComponent(currentGroupId) : '';

        try {
            const r = await fetch('/investigation/api/ttp-coverage' + q);
            const data = await r.json();
            const payload = data.success ? data : {};
            const fromIocs = payload.from_iocs || [];
            if (!fromIocs.length) {
                iocsEl.innerHTML = '<div class="inv-empty">No IOC-TTP links in scope. Link IOCs from the MITRE ATT&CK page.</div>';
            } else {
                iocsEl.innerHTML = renderTtpTable(fromIocs, 'ioc');
            }

            const fromLogs = payload.from_logs || [];
            if (!fromLogs.length) {
                logsEl.innerHTML = '<div class="inv-empty">No techniques from log analysis yet.</div>';
            } else {
                logsEl.innerHTML = renderTtpTable(fromLogs, 'log');
            }
        } catch (err) {
            iocsEl.innerHTML = '<div class="inv-empty">Error loading coverage.</div>';
            logsEl.innerHTML = '<div class="inv-empty">Error loading coverage.</div>';
        }
    }

    function renderTtpTable(rows, kind) {
        let html = '<div class="inv-table-wrap"><table class="inv-table"><thead><tr>';
        if (kind === 'ioc') {
            html += '<th>Technique</th><th>IOCs</th></tr></thead><tbody>';
            rows.forEach(function (row) {
                html += '<tr><td><span class="inv-technique-id">' + escapeHtml(row.technique_id) +
                    '</span></td><td>' + escapeHtml(row.ioc_count) + '</td></tr>';
            });
        } else {
            html += '<th>Technique</th><th>Tactic</th><th>Events</th></tr></thead><tbody>';
            rows.forEach(function (row) {
                html += '<tr><td><span class="inv-technique-id">' + escapeHtml(row.technique_id) +
                    '</span> ' + escapeHtml(row.technique_name || '') + '</td><td>' +
                    escapeHtml(row.tactic || '-') + '</td><td>' + escapeHtml(row.event_count) + '</td></tr>';
            });
        }
        html += '</tbody></table></div>';
        return html;
    }

    document.getElementById('btn-refresh-deliverables')?.addEventListener('click', loadDeliverables);
    document.getElementById('btn-refresh-ttp')?.addEventListener('click', loadTtpCoverage);

    function checkFlashDraft() {
        const hint = document.getElementById('flash-draft-hint');
        if (!hint) return;
        try {
            const draft = localStorage.getItem('flint_draft');
            if (draft) {
                const parsed = JSON.parse(draft);
                hint.textContent = 'Flash Report draft in browser: ' + (parsed.reference || parsed.subject || 'unsaved');
            }
        } catch (e) {
            /* ignore */
        }
    }

    async function refreshSessionStats() {
        try {
            const r = await fetch('/investigation/api/session');
            const data = await r.json();
            if (data.success && data.stats) renderStats(data.stats);
        } catch (e) { /* ignore */ }
    }

    updateScopedLinks(currentGroupId);
    checkFlashDraft();

    const hash = window.location.hash.replace('#', '');
    if (hash === 'deliverables' || hash === 'ttp') {
        document.querySelector('.inv-tab[data-tab="' + hash + '"]')?.click();
    }
})();
