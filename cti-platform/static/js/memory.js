(function () {
    'use strict';

    const boot = window.MEMORY_BOOT || {};
    const available = !!boot.available;

    const tabs = document.querySelectorAll('.mem-tab');
    const panels = document.querySelectorAll('.mem-panel');

    tabs.forEach(function (tab) {
        tab.addEventListener('click', function () {
            const name = tab.getAttribute('data-tab');
            tabs.forEach(function (t) { t.classList.toggle('is-active', t === tab); });
            panels.forEach(function (p) {
                const active = p.id === 'tab-' + name;
                p.classList.toggle('is-active', active);
                p.hidden = !active;
            });
            if (name === 'stats') loadStats();
        });
    });

    function esc(text) {
        if (text == null) return '';
        const d = document.createElement('div');
        d.textContent = String(text);
        return d.innerHTML;
    }

    function renderNotes(container, notes, emptyMsg) {
        if (!container) return;
        if (!notes || !notes.length) {
            container.innerHTML = '<div class="mem-empty">' + esc(emptyMsg || 'No results.') + '</div>';
            return;
        }
        container.innerHTML = notes.map(function (n) {
            const meta = [n.id, n.domain, n.tier].filter(Boolean).join(' · ');
            return '<div class="mem-note"><div class="mem-note-meta">' + esc(meta) +
                '</div><div class="mem-note-body">' + esc(n.content) + '</div></div>';
        }).join('');
    }

    function guardAvailable() {
        if (!available) {
            alert('CTI Memory is unavailable. Install zettelforge and restart the platform.');
            return false;
        }
        return true;
    }

    document.getElementById('mem-recall-form')?.addEventListener('submit', async function (e) {
        e.preventDefault();
        if (!guardAvailable()) return;
        const q = document.getElementById('mem-recall-q').value.trim();
        if (q.length < 2) return;
        const el = document.getElementById('mem-recall-results');
        el.innerHTML = '<div class="mem-empty">Searching...</div>';
        try {
            const r = await fetch('/memory/api/recall?q=' + encodeURIComponent(q));
            const data = await r.json();
            if (!r.ok || !data.success) {
                el.innerHTML = '<div class="mem-empty">' + esc(data.error || 'Search failed') + '</div>';
                return;
            }
            renderNotes(el, data.notes, 'No memory entries matched.');
        } catch (err) {
            el.innerHTML = '<div class="mem-empty">Error: ' + esc(err.message) + '</div>';
        }
    });

    async function loadStats() {
        const el = document.getElementById('mem-stats-content');
        if (!el || !available) {
            if (el) el.innerHTML = '<div class="mem-empty">CTI Memory unavailable.</div>';
            return;
        }
        el.innerHTML = '<div class="mem-empty">Loading...</div>';
        try {
            const r = await fetch('/memory/api/stats');
            const data = await r.json();
            if (!r.ok || !data.success) {
                el.innerHTML = '<div class="mem-empty">' + esc(data.error || 'Failed to load stats') + '</div>';
                return;
            }
            const s = data;
            let html = '<div class="mem-stats-grid">';
            html += statBlock(s.total_notes || 0, 'Notes');
            html += statBlock(s.notes_created || 0, 'Created');
            html += statBlock(s.retrievals || 0, 'Retrievals');
            html += statBlock((s.entity_index && Object.keys(s.entity_index).length) || 0, 'Entity types');
            html += '</div>';

            const top = s.top_entities || [];
            if (top.length) {
                html += '<h3 class="mem-hint" style="text-transform:uppercase;font-weight:600;">Most referenced entities</h3>';
                html += '<div class="mem-table-wrap"><table class="mem-table"><thead><tr><th>Type</th><th>Unique</th><th>Mappings</th></tr></thead><tbody>';
                top.forEach(function (row) {
                    html += '<tr><td>' + esc(row.type) + '</td><td>' + esc(row.unique_entities) +
                        '</td><td>' + esc(row.total_mappings) + '</td></tr>';
                });
                html += '</tbody></table></div>';
            }
            el.innerHTML = html;
        } catch (err) {
            el.innerHTML = '<div class="mem-empty">Error: ' + esc(err.message) + '</div>';
        }
    }

    function statBlock(value, label) {
        return '<div class="mem-stat"><span class="mem-stat-value">' + esc(value) +
            '</span><span class="mem-stat-label">' + esc(label) + '</span></div>';
    }

    document.getElementById('mem-refresh-stats')?.addEventListener('click', loadStats);

    document.getElementById('mem-entity-form')?.addEventListener('submit', async function (e) {
        e.preventDefault();
        if (!guardAvailable()) return;
        const type = document.getElementById('mem-entity-type').value;
        const value = document.getElementById('mem-entity-value').value.trim();
        const el = document.getElementById('mem-entity-results');
        el.innerHTML = '<div class="mem-empty">Looking up...</div>';
        try {
            const r = await fetch('/memory/api/entity?type=' + encodeURIComponent(type) +
                '&value=' + encodeURIComponent(value));
            const data = await r.json();
            if (!r.ok || !data.success) {
                el.innerHTML = '<div class="mem-empty">' + esc(data.error || 'Lookup failed') + '</div>';
                return;
            }
            let html = '';
            if (data.relationships && data.relationships.length) {
                html += '<p class="mem-hint"><strong>Relationships:</strong> ' + data.relationships.length + '</p>';
            }
            html += '<div id="mem-entity-notes"></div>';
            el.innerHTML = html;
            renderNotes(document.getElementById('mem-entity-notes'), data.notes, 'No notes for this entity.');
        } catch (err) {
            el.innerHTML = '<div class="mem-empty">Error: ' + esc(err.message) + '</div>';
        }
    });

    document.getElementById('mem-graph-form')?.addEventListener('submit', async function (e) {
        e.preventDefault();
        if (!guardAvailable()) return;
        const type = document.getElementById('mem-graph-type').value;
        const value = document.getElementById('mem-graph-value').value.trim();
        const depth = document.getElementById('mem-graph-depth').value;
        const el = document.getElementById('mem-graph-results');
        el.innerHTML = '<div class="mem-empty">Traversing graph...</div>';
        try {
            const r = await fetch('/memory/api/graph?type=' + encodeURIComponent(type) +
                '&value=' + encodeURIComponent(value) + '&depth=' + encodeURIComponent(depth));
            const data = await r.json();
            if (!r.ok || !data.success) {
                el.innerHTML = '<div class="mem-empty">' + esc(data.error || 'Traversal failed') + '</div>';
                return;
            }
            const edges = data.edges || [];
            if (!edges.length) {
                el.innerHTML = '<div class="mem-empty">No graph edges found from this entity.</div>';
                return;
            }
            el.innerHTML = edges.map(function (edge) {
                return '<div class="mem-edge">' + esc(edge.from_type) + ' / ' + esc(edge.from_value) +
                    ' —[' + esc(edge.relationship) + ']→ ' + esc(edge.to_type) + ' / ' + esc(edge.to_value) + '</div>';
            }).join('');
        } catch (err) {
            el.innerHTML = '<div class="mem-empty">Error: ' + esc(err.message) + '</div>';
        }
    });

    document.getElementById('mem-add-form')?.addEventListener('submit', async function (e) {
        e.preventDefault();
        if (!guardAvailable()) return;
        const content = document.getElementById('mem-add-content').value.trim();
        const fb = document.getElementById('mem-add-feedback');
        fb.textContent = 'Storing...';
        fb.className = 'mem-feedback';
        try {
            const r = await fetch('/memory/api/remember', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content }),
            });
            const data = await r.json();
            if (!r.ok || !data.success) {
                fb.textContent = data.error || 'Failed';
                fb.className = 'mem-feedback error';
                return;
            }
            fb.textContent = 'Stored (' + (data.note && data.note.id ? data.note.id : 'ok') + ').';
            fb.className = 'mem-feedback success';
            document.getElementById('mem-add-content').value = '';
        } catch (err) {
            fb.textContent = 'Error: ' + err.message;
            fb.className = 'mem-feedback error';
        }
    });

    async function ingestRule(formId, url, feedbackId) {
        const form = document.getElementById(formId);
        const fb = document.getElementById(feedbackId);
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            if (!guardAvailable()) return;
            fb.textContent = 'Ingesting...';
            fb.className = 'mem-feedback';
            const fd = new FormData(form);
            try {
                const r = await fetch(url, { method: 'POST', body: fd });
                const data = await r.json();
                if (!r.ok || !data.success) {
                    fb.textContent = data.error || 'Ingest failed';
                    fb.className = 'mem-feedback error';
                    return;
                }
                fb.textContent = data.message || 'Ingested successfully.';
                fb.className = 'mem-feedback success';
                form.reset();
            } catch (err) {
                fb.textContent = 'Error: ' + err.message;
                fb.className = 'mem-feedback error';
            }
        });
    }

    ingestRule('mem-sigma-form', '/memory/api/ingest/sigma', 'mem-sigma-feedback');
    ingestRule('mem-yara-form', '/memory/api/ingest/yara', 'mem-yara-feedback');

    if (available) loadStats();

    if (window.location.hash === '#search') {
        document.querySelector('.mem-tab[data-tab="search"]')?.click();
    }
})();
