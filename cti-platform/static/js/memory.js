(function () {
    'use strict';

    const boot = window.MEMORY_BOOT || {};
    const available = !!boot.available;
    const PREVIEW_CHARS = 320;

    const titleInput = document.getElementById('mem-add-title');
    const composeInput = document.getElementById('mem-add-content');
    const saveBtn = document.getElementById('mem-save-btn');
    const feedback = document.getElementById('mem-add-feedback');
    const searchInput = document.getElementById('mem-search');
    const unifiedEl = document.getElementById('mem-unified-results');
    const feedEl = document.getElementById('mem-feed');
    const feedTitle = document.getElementById('mem-feed-title');
    const feedCount = document.getElementById('mem-feed-count');
    const attachBanner = document.getElementById('mem-attach-banner');
    const attachTitle = document.getElementById('mem-attach-title');
    const attachDesc = document.getElementById('mem-attach-desc');
    const attachClear = document.getElementById('mem-attach-clear');
    const composeEl = document.getElementById('mem-compose');

    let searchTimer = null;
    let searchAbort = null;
    let searchSeq = 0;
    let attachContext = null;
    let editingId = null;
    let expandedNotes = new Set();
    let lastNotes = [];
    let lastEmptyMsg = 'No notes yet.';

    function esc(text) {
        if (text == null) return '';
        const d = document.createElement('div');
        d.textContent = String(text);
        return d.innerHTML;
    }

    function guardAvailable() {
        if (!available) {
            alert('Memory is unavailable. Install zettelforge and restart the platform.');
            return false;
        }
        return true;
    }

    function showToast(msg, kind) {
        if (!feedback) return;
        feedback.hidden = false;
        feedback.textContent = msg;
        feedback.setAttribute('data-kind', kind || 'success');
    }

    function hideToast() {
        if (feedback) feedback.hidden = true;
    }

    function autoResize(textarea) {
        if (!textarea) return;
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 320) + 'px';
    }

    function formatWhen(note) {
        const raw = note.updated_at || note.created_at;
        if (!raw) return '';
        try {
            const d = new Date(raw);
            if (Number.isNaN(d.getTime())) return '';
            const diff = Date.now() - d.getTime();
            const mins = Math.floor(diff / 60000);
            if (mins < 1) return 'Just now';
            if (mins < 60) return mins + ' min ago';
            const hrs = Math.floor(mins / 60);
            if (hrs < 24) return hrs + ' h ago';
            const days = Math.floor(hrs / 24);
            if (days < 7) return days + ' d ago';
            return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        } catch (_) {
            return '';
        }
    }

    function scrollToCompose() {
        composeEl?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        titleInput?.focus();
    }

    function setAttach(ctx) {
        attachContext = ctx;
        if (!attachBanner) return;
        if (!ctx) {
            attachBanner.hidden = true;
            return;
        }
        attachBanner.hidden = false;
        if (ctx.kind === 'ioc') {
            attachTitle.textContent = 'Note for IOC';
            attachDesc.textContent = (ctx.ioc_type || ctx.type || 'ioc') + ': ' + (ctx.value || ('#' + ctx.id));
        } else if (ctx.kind === 'ttp') {
            attachTitle.textContent = 'Note for TTP';
            attachDesc.textContent = (ctx.id || ctx.value || '') + (ctx.name ? ' · ' + ctx.name : '');
        } else if (ctx.kind === 'log') {
            attachTitle.textContent = 'Note for log incident';
            attachDesc.textContent = ctx.name || ctx.id || '';
        } else if (ctx.kind === 'entity') {
            attachTitle.textContent = 'Note for ' + (ctx.label || ctx.entity_type || 'indicator');
            attachDesc.textContent = (ctx.name ? ctx.name + ' · ' : '') + (ctx.value || '');
        } else {
            attachTitle.textContent = 'Linked note';
            attachDesc.textContent = ctx.label || ctx.value || '';
        }
    }

    function attachFromUrl(url) {
        if (!url) return;
        try {
            const u = new URL(url, window.location.origin);
            const p = u.searchParams;
            const attach = p.get('attach');
            if (attach === 'ioc' && p.get('id')) {
                setAttach({
                    kind: 'ioc',
                    id: parseInt(p.get('id'), 10),
                    value: p.get('value') || '',
                    ioc_type: p.get('type') || p.get('ioc_type') || 'ioc',
                    type: p.get('type') || 'ioc',
                });
            } else if (attach === 'ttp') {
                setAttach({
                    kind: 'ttp',
                    id: (p.get('id') || p.get('technique') || '').toUpperCase(),
                    name: p.get('name') || '',
                });
            } else if (attach === 'log' && p.get('id')) {
                setAttach({ kind: 'log', id: p.get('id'), name: p.get('name') || p.get('id') });
            } else if (attach === 'entity' || attach === 'value') {
                setAttach({
                    kind: 'entity',
                    entity_type: p.get('entity_type') || p.get('type') || '',
                    value: p.get('value') || '',
                });
            }
            scrollToCompose();
        } catch (_) { /* ignore */ }
    }

    window.memAttachFromUrl = attachFromUrl;

    function applyAttachFromUrl() {
        const params = new URLSearchParams(window.location.search);
        const attach = params.get('attach');
        if (!attach) return;
        if (attach === 'ioc') {
            const id = parseInt(params.get('id') || params.get('ioc_id') || '0', 10);
            if (id) {
                setAttach({
                    kind: 'ioc',
                    id: id,
                    value: params.get('value') || '',
                    ioc_type: params.get('type') || params.get('ioc_type') || 'ioc',
                    type: params.get('type') || 'ioc',
                });
            }
        } else if (attach === 'ttp') {
            setAttach({
                kind: 'ttp',
                id: (params.get('id') || params.get('technique') || '').toUpperCase(),
                name: params.get('name') || '',
            });
        } else if (attach === 'log') {
            setAttach({ kind: 'log', id: params.get('id') || '', name: params.get('name') || '' });
        } else if (attach === 'entity' || attach === 'value') {
            setAttach({
                kind: 'entity',
                entity_type: params.get('entity_type') || params.get('type') || '',
                value: params.get('value') || '',
                name: params.get('name') || '',
            });
        }
        scrollToCompose();
    }

    function renderEntityChips(entities, note) {
        if (!entities || !entities.length) return '';
        let html = '<div class="mem-entities"><span class="mem-entities-label">Detected</span>';
        entities.forEach(function (ent) {
            const kind = ent.kind || 'other';
            html += '<button type="button" class="mem-chip mem-chip--' + esc(kind) + '" ' +
                'data-search-value="' + esc(ent.value) + '" title="Search workspace">' +
                '<span class="mem-chip-type">' + esc(ent.label || ent.type) + '</span>' +
                '<span class="mem-chip-val">' + esc(ent.value) + '</span></button>';
        });
        if (note.entities_search_url) {
            html += '<a class="mem-chip mem-chip--all" href="' + esc(note.entities_search_url) + '">Search all</a>';
        }
        html += '</div>';
        return html;
    }

    function renderNoteCard(note, opts) {
        opts = opts || {};
        const highlightId = opts.highlightId;
        const isHit = highlightId && note.id === highlightId;
        const isEditing = editingId === note.id;
        const isExpanded = expandedNotes.has(note.id);
        const cls = 'mem-card' + (isHit ? ' mem-card--highlight' : '') + (isEditing ? ' mem-card--edit' : '');
        const when = formatWhen(note);
        const linkUrl = note.links && note.links.url;
        const linkLabel = note.links && note.links.label;
        const linkHtml = linkUrl
            ? '<a class="mem-card-link" href="' + esc(linkUrl) + '">' + esc(linkLabel || 'Open record') + '</a>'
            : '';
        const displayTitle = note.title || (note.content || '').split('\n')[0].slice(0, 80);
        const body = note.content || '';
        const isLong = note.is_long || body.length > PREVIEW_CHARS;
        const showFull = isExpanded || !isLong;
        const bodyShown = showFull ? body : (note.content_preview || body.slice(0, PREVIEW_CHARS) + '…');

        let bodyHtml;
        if (isEditing) {
            bodyHtml = '<input type="text" class="mem-edit-title" data-edit-title="' + esc(note.id) + '" value="' + esc(note.title || '') + '" placeholder="Title">' +
                '<textarea class="mem-edit-input" data-edit-id="' + esc(note.id) + '">' + esc(body) + '</textarea>' +
                '<div class="mem-edit-actions">' +
                '<button type="button" class="mem-edit-save" data-id="' + esc(note.id) + '">Save</button>' +
                '<button type="button" class="mem-edit-cancel">Cancel</button></div>';
        } else {
            bodyHtml = '<div class="mem-card-body' + (showFull ? '' : ' mem-card-body--clamped') + '">' + esc(bodyShown) + '</div>';
            if (isLong) {
                bodyHtml += '<button type="button" class="mem-expand-btn" data-expand-id="' + esc(note.id) + '">' +
                    (isExpanded ? 'Show less' : 'Show more') + '</button>';
            }
        }

        return '<article class="' + cls + '" data-note-id="' + esc(note.id) + '">' +
            '<div class="mem-card-head">' +
            '<div class="mem-card-meta">' +
            (displayTitle ? '<h3 class="mem-card-title">' + esc(displayTitle) + '</h3>' : '') +
            (when ? '<span class="mem-card-time">' + esc(when) + '</span>' : '') +
            linkHtml +
            '</div>' +
            '<div class="mem-card-actions">' +
            '<button type="button" class="mem-icon-btn mem-edit-btn" data-id="' + esc(note.id) + '">Edit</button>' +
            '<button type="button" class="mem-icon-btn mem-del-btn" data-id="' + esc(note.id) + '">Delete</button>' +
            '</div></div>' +
            renderEntityChips(note.entities, note) +
            bodyHtml +
            '</article>';
    }

    function bindCardActions(container) {
        container.querySelectorAll('.mem-chip[data-search-value]').forEach(function (chip) {
            chip.addEventListener('click', function () {
                const val = chip.getAttribute('data-search-value');
                if (val && searchInput) {
                    searchInput.value = val;
                    runUnifiedSearch(val);
                }
            });
        });
        container.querySelectorAll('.mem-expand-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                const id = btn.getAttribute('data-expand-id');
                if (expandedNotes.has(id)) expandedNotes.delete(id);
                else expandedNotes.add(id);
                renderNotes(feedEl, lastNotes, lastEmptyMsg);
            });
        });
        container.querySelectorAll('.mem-edit-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                editingId = btn.getAttribute('data-id');
                renderNotes(feedEl, lastNotes, lastEmptyMsg);
            });
        });
        container.querySelectorAll('.mem-del-btn').forEach(function (btn) {
            btn.addEventListener('click', function () { deleteNote(btn.getAttribute('data-id')); });
        });
        container.querySelectorAll('.mem-edit-save').forEach(function (btn) {
            btn.addEventListener('click', function () { saveEdit(btn.getAttribute('data-id'), container); });
        });
        container.querySelectorAll('.mem-edit-cancel').forEach(function (btn) {
            btn.addEventListener('click', function () {
                editingId = null;
                renderNotes(feedEl, lastNotes, lastEmptyMsg);
            });
        });
        if (container.querySelector('[data-note-id]')) {
            container.querySelectorAll('[data-note-id]').forEach(function (node) {
                const hid = new URLSearchParams(window.location.search).get('note');
                if (hid && node.getAttribute('data-note-id') === hid) {
                    node.scrollIntoView({ block: 'center', behavior: 'smooth' });
                }
            });
        }
    }

    function renderNotes(container, notes, emptyMsg, highlightId) {
        if (!container) return;
        lastNotes = notes || [];
        lastEmptyMsg = emptyMsg || lastEmptyMsg;
        if (!notes || !notes.length) {
            container.innerHTML = '<div class="mem-feed-empty">' + esc(emptyMsg) + '</div>';
            return;
        }
        container.innerHTML = notes.map(function (n) {
            return renderNoteCard(n, { highlightId: highlightId });
        }).join('');
        bindCardActions(container);
    }

    function setFeedMeta(title, count) {
        if (feedTitle) feedTitle.textContent = title;
        if (feedCount) feedCount.textContent = count != null ? count + ' note' + (count === 1 ? '' : 's') : '';
    }

    async function loadRecent() {
        if (!feedEl || !available) return;
        setFeedMeta('Your notes', null);
        feedEl.innerHTML = '<div class="mem-feed-loading">Loading…</div>';
        editingId = null;
        if (unifiedEl) unifiedEl.hidden = true;
        try {
            const r = await fetch('/memory/api/recent?k=12');
            const data = await r.json();
            if (!r.ok || !data.success) {
                feedEl.innerHTML = '<div class="mem-feed-empty">' + esc(data.error || 'Could not load notes.') + '</div>';
                return;
            }
            setFeedMeta('Your notes', data.count || 0);
            renderNotes(feedEl, data.notes, 'No notes yet. Search above or write a note below.');
        } catch (err) {
            feedEl.innerHTML = '<div class="mem-feed-empty">Error: ' + esc(err.message) + '</div>';
        }
    }

    function unifiedSection(label, itemsHtml) {
        if (!itemsHtml) return '';
        return '<div class="mem-uni-section"><h3 class="mem-uni-label">' + label + '</h3><div class="mem-uni-list">' + itemsHtml + '</div></div>';
    }

    function uniRow(icon, title, sub, actionsHtml) {
        return '<div class="mem-uni-row">' +
            '<span class="mem-uni-icon">' + icon + '</span>' +
            '<div class="mem-uni-body"><div class="mem-uni-title">' + esc(title) + '</div>' +
            (sub ? '<div class="mem-uni-sub">' + esc(sub) + '</div>' : '') + '</div>' +
            '<div class="mem-uni-actions">' + actionsHtml + '</div></div>';
    }

    function renderUnifiedResults(d) {
        if (!unifiedEl) return;
        const sections = [];

        if (d.iocs && d.iocs.length) {
            let block = '';
            d.iocs.forEach(function (ioc) {
                block += uniRow('IOC',
                    ioc.ioc_value,
                    ioc.ioc_type + (ioc.primary_source ? ' · ' + ioc.primary_source : ''),
                    '<a class="mem-uni-link" href="/ioc/' + ioc.id + '">Open</a>' +
                    '<button type="button" class="mem-uni-note" data-attach-url="' + esc(ioc.attach_url || '') + '">Add note</button>'
                );
            });
            sections.push(unifiedSection('IOCs', block));
        }

        if (d.mitre && d.mitre.length) {
            let block = '';
            d.mitre.forEach(function (m) {
                const sub = m.kind === 'technique' ? (m.tactic || 'Technique') : 'Threat group';
                block += uniRow('MITRE', m.id + ' · ' + m.name, sub,
                    '<a class="mem-uni-link" href="' + esc(m.url || '#') + '">Open</a>' +
                    '<button type="button" class="mem-uni-note" data-attach-url="' + esc(m.attach_url || '') + '">Add note</button>'
                );
            });
            sections.push(unifiedSection('MITRE ATT&CK', block));
        }

        if (d.sources && d.sources.length) {
            let block = '';
            d.sources.forEach(function (s) {
                block += uniRow('SRC', s.name, (s.source_type || '') + ' · ' + (s.ioc_count || 0) + ' IOCs',
                    '<a class="mem-uni-link" href="' + esc(s.url || '/sources') + '">Open</a>' +
                    '<button type="button" class="mem-uni-note" data-attach-url="' + esc(s.attach_url || '') + '">Add note</button>'
                );
            });
            sections.push(unifiedSection('Sources', block));
        }

        if (d.memory && d.memory.length) {
            let block = '';
            d.memory.forEach(function (n) {
                const t = n.title || (n.content || '').slice(0, 60);
                block += uniRow('NOTE', t, (n.content || '').slice(0, 100),
                    '<a class="mem-uni-link" href="' + esc((n.links && n.links.memory_url) || '/memory') + '">View</a>'
                );
            });
            sections.push(unifiedSection('Notes', block));
        }

        if (!sections.length) {
            unifiedEl.innerHTML = '<div class="mem-feed-empty">No workspace results for “' + esc(d.query) + '”.</div>';
        } else {
            unifiedEl.innerHTML = sections.join('');
        }
        unifiedEl.hidden = false;

        unifiedEl.querySelectorAll('.mem-uni-note[data-attach-url]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                attachFromUrl(btn.getAttribute('data-attach-url'));
            });
        });
    }

    async function runUnifiedSearch(query, highlightNoteId) {
        if (!guardAvailable()) return;
        const q = (query || '').trim();
        if (q.length < 2) {
            loadRecent();
            return;
        }

        if (unifiedEl) {
            unifiedEl.hidden = false;
            unifiedEl.innerHTML = '<div class="mem-feed-loading">Searching workspace…</div>';
        }
        setFeedMeta('Matching notes', null);
        feedEl.innerHTML = '<div class="mem-feed-loading">Loading notes…</div>';
        editingId = null;

        if (searchAbort) searchAbort.abort();
        searchAbort = new AbortController();
        const seq = ++searchSeq;

        try {
            const r = await fetch('/api/global-search?q=' + encodeURIComponent(q) + '&scope=workspace', {
                signal: searchAbort.signal,
            });
            if (seq !== searchSeq) return;
            const data = await r.json();
            if (!r.ok || !data.success) {
                if (unifiedEl) unifiedEl.innerHTML = '<div class="mem-feed-empty">Search failed.</div>';
                return;
            }
            renderUnifiedResults(data);
            const memNotes = data.memory || [];
            setFeedMeta('Matching notes', memNotes.length);
            renderNotes(feedEl, memNotes, 'No notes match this query.', highlightNoteId);
        } catch (err) {
            if (err && err.name === 'AbortError') return;
            if (seq !== searchSeq) return;
            if (unifiedEl) unifiedEl.innerHTML = '<div class="mem-feed-empty">Error: ' + esc(err.message) + '</div>';
        }
    }

    async function saveNote() {
        if (!guardAvailable()) return;
        const title = (titleInput?.value || '').trim();
        const content = (composeInput?.value || '').trim();
        if (!content && !title) {
            showToast('Add a title or note body.', 'error');
            return;
        }
        if (saveBtn) saveBtn.disabled = true;
        hideToast();
        const payload = { content: content, title: title };
        if (attachContext) payload.attach = attachContext;
        try {
            const r = await fetch('/memory/api/remember', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await r.json();
            if (!r.ok || !data.success) {
                showToast(data.error || 'Could not save', 'error');
                return;
            }
            if (titleInput) titleInput.value = '';
            if (composeInput) composeInput.value = '';
            autoResize(composeInput);
            const memoryFailed = data.memory_index_status === 'failed';
            showToast(
                memoryFailed
                    ? 'Saved to the IOC, but CTI Memory indexing failed.'
                    : 'Saved',
                memoryFailed ? 'error' : 'success'
            );
            setTimeout(hideToast, 2000);
            const q = searchInput?.value.trim();
            if (q && q.length >= 2) runUnifiedSearch(q);
            else loadRecent();
        } catch (err) {
            showToast('Error: ' + err.message, 'error');
        } finally {
            if (saveBtn) saveBtn.disabled = false;
        }
    }

    async function saveEdit(noteId, container) {
        const ta = container.querySelector('[data-edit-id="' + noteId + '"]');
        const ti = container.querySelector('[data-edit-title="' + noteId + '"]');
        if (!ta) return;
        const content = ta.value.trim();
        const title = ti ? ti.value.trim() : undefined;
        if (!content && !title) {
            alert('Note cannot be empty.');
            return;
        }
        try {
            const r = await fetch('/memory/api/note/' + encodeURIComponent(noteId), {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content, title: title }),
            });
            const data = await r.json();
            if (!r.ok || !data.success) {
                alert(data.error || 'Update failed');
                return;
            }
            editingId = null;
            const q = searchInput?.value.trim();
            if (q && q.length >= 2) runUnifiedSearch(q);
            else loadRecent();
        } catch (err) {
            alert('Error: ' + err.message);
        }
    }

    async function deleteNote(noteId) {
        if (!noteId || !confirm('Delete this note permanently?')) return;
        try {
            const r = await fetch('/memory/api/note/' + encodeURIComponent(noteId), { method: 'DELETE' });
            const data = await r.json();
            if (!r.ok || !data.success) {
                alert(data.error || 'Delete failed');
                return;
            }
            editingId = null;
            expandedNotes.delete(noteId);
            const q = searchInput?.value.trim();
            if (q && q.length >= 2) runUnifiedSearch(q);
            else loadRecent();
        } catch (err) {
            alert('Error: ' + err.message);
        }
    }

    saveBtn?.addEventListener('click', saveNote);
    composeInput?.addEventListener('input', function () { autoResize(composeInput); });
    composeInput?.addEventListener('keydown', function (e) {
        if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
            e.preventDefault();
            saveNote();
        }
    });

    searchInput?.addEventListener('input', function () {
        clearTimeout(searchTimer);
        const q = searchInput.value.trim();
        searchTimer = setTimeout(function () {
            if (q.length < 2) loadRecent();
            else runUnifiedSearch(q);
        }, 240);
    });

    attachClear?.addEventListener('click', function () {
        setAttach(null);
        if (composeInput) composeInput.placeholder = 'Your analysis, context, hypotheses…';
    });

    function applyDeepLink() {
        if (!available) return;
        applyAttachFromUrl();
        const params = new URLSearchParams(window.location.search);
        const q = (params.get('q') || '').trim();
        const noteId = (params.get('note') || '').trim();
        if (q) {
            if (searchInput) searchInput.value = q;
            runUnifiedSearch(q, noteId || null);
        }
    }

    if (available) {
        autoResize(composeInput);
        const params = new URLSearchParams(window.location.search);
        if (params.get('q') || params.get('note')) {
            applyDeepLink();
        } else if (!params.get('attach')) {
            loadRecent();
        } else {
            applyAttachFromUrl();
            loadRecent();
        }
    }
})();
