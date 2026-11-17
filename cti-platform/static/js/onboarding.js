(function () {
    'use strict';

    try {
        localStorage.setItem('odysafe_onboarding_seen', '1');
    } catch (e) { /* ignore */ }

    var reveals = document.querySelectorAll('.ob-reveal');
    if (!reveals.length || !('IntersectionObserver' in window)) {
        reveals.forEach(function (el) { el.classList.add('is-visible'); });
        return;
    }

    var observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('is-visible');
                observer.unobserve(entry.target);
            }
        });
    }, { root: null, rootMargin: '0px 0px -8% 0px', threshold: 0.08 });

    reveals.forEach(function (el) { observer.observe(el); });
})();
