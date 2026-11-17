(function () {
    'use strict';

    const overlay = document.getElementById('gs-overlay');
    const input   = document.getElementById('gs-input');
    const results = document.getElementById('gs-results');
    if (!overlay || !input || !results) return;

    let _timer   = null;
    let _active  = -1;
    let _abort   = null;
    let _seq     = 0;

    /* ── open / close ── */
    function open() {
        overlay.style.display = 'flex';
        input.value = '';
        results.innerHTML = '';
        _active = -1;
        if (_abort) { _abort.abort(); _abort = null; }
        setTimeout(() => input.focus(), 30);
    }

    function close() {
        overlay.style.display = 'none';
        input.value = '';
        results.innerHTML = '';
        _active = -1;
        if (_abort) { _abort.abort(); _abort = null; }
    }

    /* ── keyboard global ── */
    document.addEventListener('keydown', function (e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            overlay.style.display === 'none' ? open() : close();
            return;
        }
        if (overlay.style.display === 'none') return;
        if (e.key === 'Escape')    { close(); return; }
        if (e.key === 'ArrowDown') { e.preventDefault(); moveActive(1); }
        if (e.key === 'ArrowUp')   { e.preventDefault(); moveActive(-1); }
        if (e.key === 'Enter')     { e.preventDefault(); activateItem(); }
    });

    overlay.addEventListener('mousedown', function (e) {
        if (e.target === overlay) close();
    });

    function getRows() {
        return Array.from(results.querySelectorAll('.gs-item'));
    }

    function moveActive(dir) {
        const rows = getRows();
        if (!rows.length) return;
        rows.forEach(r => r.classList.remove('gs-active'));
        _active = Math.max(0, Math.min(rows.length - 1, _active + dir));
        rows[_active].classList.add('gs-active');
        rows[_active].scrollIntoView({ block: 'nearest' });
    }

    function activateItem() {
        const rows = getRows();
        const target = rows[_active] || rows[0];
        if (target && target.href) { close(); window.location.href = target.href; }
    }

    input.addEventListener('input', function () {
        clearTimeout(_timer);
        const q = input.value.trim();
        if (q.length < 2) {
            if (_abort) { _abort.abort(); _abort = null; }
            results.innerHTML = '';
            _active = -1;
            return;
        }
        results.innerHTML = '<div class="gs-loading">Searching\u2026</div>';
        _timer = setTimeout(() => doSearch(q), 180);
    });

    function memoryUrl(note, query) {
        if (note.links && note.links.memory_url) return note.links.memory_url;
        const params = new URLSearchParams();
        if (query) params.set('q', query);
        if (note.id) params.set('note', note.id);
        const qs = params.toString();
        return qs ? '/memory?' + qs : '/memory';
    }

    async function doSearch(q) {
        if (_abort) _abort.abort();
        _abort = new AbortController();
        const seq = ++_seq;
        const signal = _abort.signal;
        try {
            const r = await fetch('/api/global-search?q=' + encodeURIComponent(q), { signal });
            if (seq !== _seq) return;
            if (!r.ok) throw new Error('HTTP ' + r.status);
            const d = await r.json();
            if (!d.success) throw new Error(d.error || 'error');
            render(d);
        } catch (err) {
            if (err && err.name === 'AbortError') return;
            if (seq !== _seq) return;
            results.innerHTML = '<div class="gs-empty">Error loading results.</div>';
        }
    }

    function esc(s) {
        return String(s || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function makeItem(icon, title, sub, url, badgeClass, badgeLabel, assocHtml) {
        assocHtml = assocHtml || '';
        return `<a class="gs-item" href="${esc(url)}">
            <span class="gs-item-icon">${icon}</span>
            <span class="gs-item-body">
                <span class="gs-item-title">${esc(title)}</span>
                <span class="gs-item-sub">${esc(sub)}</span>
            </span>
            ${assocHtml}
            <span class="gs-badge ${badgeClass}">${badgeLabel}</span>
        </a>`;
    }

    function render(d) {
        const parts = [];
        _active = -1;

        if (d.iocs && d.iocs.length) {
            parts.push('<div class="gs-section-label">IOCs</div>');
            d.iocs.forEach(function (ioc) {
                const assocParts = [];
                if (ioc.source_count > 1)
                    assocParts.push(ioc.source_count + ' sources');
                else if (ioc.primary_source)
                    assocParts.push(ioc.primary_source);
                const assocHtml = assocParts.length
                    ? '<span class="gs-assoc">' + esc(assocParts.join(' \u00b7 ')) + '</span>'
                    : '';
                const url = ioc.source_count > 1
                    ? '/iocs?value=' + encodeURIComponent(ioc.ioc_value) + '&type=' + encodeURIComponent(ioc.ioc_type)
                    : '/ioc/' + ioc.id;
                parts.push(makeItem('&#x1F50D;', ioc.ioc_value, ioc.ioc_type, url, 'gs-badge-ioc', 'IOC', assocHtml));
            });
        }

        if (d.sources && d.sources.length) {
            parts.push('<div class="gs-section-label">Sources</div>');
            d.sources.forEach(function (s) {
                const sub = [s.source_type, s.ioc_count + ' IOCs'].filter(Boolean).join(' \u00b7 ');
                const url = s.url || '/sources';
                parts.push(makeItem('&#x1F4C4;', s.name, sub, url, 'gs-badge-source', 'Source', ''));
            });
        }

        if (d.mitre && d.mitre.length) {
            parts.push('<div class="gs-section-label">MITRE ATT&amp;CK</div>');
            d.mitre.forEach(function (m) {
                const icon = m.kind === 'group' ? '&#x1F465;' : '&#x1F3AF;';
                const sub  = m.kind === 'technique' ? (m.tactic || 'Technique') : 'Threat Group';
                const url = m.url || '/cti-resources/mitre-attack';
                parts.push(makeItem(icon, m.id + ' \u2014 ' + m.name, sub, url, 'gs-badge-mitre', 'MITRE', ''));
            });
        }

        if (d.memory && d.memory.length) {
            parts.push('<div class="gs-section-label">CTI Memory</div>');
            d.memory.forEach(function (n) {
                const title = (n.content || '').slice(0, 120);
                const subParts = [n.id, n.domain].filter(Boolean);
                if (n.links && n.links.label) subParts.push(n.links.label);
                const sub = subParts.join(' \u00b7 ');
                const url = memoryUrl(n, d.query);
                parts.push(makeItem('&#x1F9E0;', title, sub, url, 'gs-badge-memory', 'Memory', ''));
            });
        }

        if (!parts.length) {
            results.innerHTML = '<div class="gs-empty">No results for &ldquo;' + esc(d.query) + '&rdquo;</div>';
            return;
        }

        results.innerHTML = parts.join('');

        getRows().forEach(function (row, i) {
            row.addEventListener('mouseenter', function () { _active = i; });
        });
    }
}());
