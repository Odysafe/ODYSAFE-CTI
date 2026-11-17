(() => {
    const catalog = window.CTI_TRANSLATIONS;
    const cookieName = 'odysafe_cti_language';
    const sourceNodes = new WeakMap();
    const title = document.title;
    const attributes = ['title', 'aria-label', 'placeholder', 'alt'];
    const selector = ['[data-cti-label]', ...attributes.map(name => `[data-cti-${name}]`)].join(',');
    const languageControl = document.getElementById('cti-language');
    let language = document.cookie.split(';').some(cookie => cookie.trim() === `${cookieName}=fr`) ? 'fr' : 'en';

    function t(source) {
        return language === 'fr' && Object.hasOwn(catalog, source) ? catalog[source] : source;
    }

    function setText(element, source) {
        if (!element) return;
        element.dataset.ctiLabel = source;
        const label = t(source);
        if (element.textContent !== label) element.textContent = label;
    }

    function apply(root) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_COMMENT);
        while (walker.nextNode()) {
            const marker = walker.currentNode;
            const node = marker.nextSibling;
            if (marker.data !== 'cti-i18n' || node?.nodeType !== Node.TEXT_NODE) continue;
            if (!sourceNodes.has(node)) sourceNodes.set(node, node.data);
            const original = sourceNodes.get(node);
            const source = original.replace(/\s+/g, ' ').trim();
            const label = t(source);
            const translated = label === source ? original : original.replace(/\S[\s\S]*\S|\S/, () => label);
            if (node.data !== translated) node.data = translated;
        }

        const elements = [...root.querySelectorAll(selector)];
        if (root.matches?.(selector)) elements.unshift(root);
        for (const element of elements) {
            if (element.hasAttribute('data-cti-label')) setText(element, element.dataset.ctiLabel);
            for (const name of attributes) {
                const source = element.getAttribute(`data-cti-${name}`);
                if (source !== null && element.getAttribute(name) !== t(source)) {
                    element.setAttribute(name, t(source));
                }
            }
        }
    }

    function switchLanguage(value, persist = false) {
        language = value;
        document.documentElement.lang = language;
        document.title = t(title);
        if (persist) {
            const secure = location.protocol === 'https:' ? '; Secure' : '';
            document.cookie = `${cookieName}=${language}; Path=/; Max-Age=31536000; SameSite=Strict${secure}`;
        }
        apply(document);
        if (languageControl) languageControl.value = language;
    }

    window.CTI_I18N = {t, setText};
    languageControl?.addEventListener('change', () => switchLanguage(languageControl.value, true));
    new MutationObserver(records => {
        const added = new Set();
        for (const record of records) {
            for (const node of record.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE && node.isConnected) added.add(node);
            }
        }
        for (const node of added) apply(node);
    }).observe(document.body, {childList: true, subtree: true});
    switchLanguage(language);
})();
