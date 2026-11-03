// ============================================
// MENU MOBILE
// ============================================

const menuToggle = document.querySelector('.menu-toggle');
const navMenu = document.querySelector('.nav-menu');

if (menuToggle && navMenu) {
    menuToggle.addEventListener('click', () => {
        navMenu.classList.toggle('active');
        menuToggle.classList.toggle('active');
    });

    // Close menu when clicking on a link
    const navLinks = document.querySelectorAll('.nav-menu a');
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            navMenu.classList.remove('active');
            menuToggle.classList.remove('active');
        });
    });
}

// ============================================
// UTILITIES
// ============================================

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================
// MODAL MANAGEMENT
// ============================================

// Close modals by clicking outside
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) {
        e.target.classList.remove('active');
    }
});

// ============================================
// INTELLIGENT LINK PREFETCHING
// ============================================

const LinkPrefetcher = {
    _prefetched: new Set(),
    _prefetchDelay: 100, // ms delay before prefetching on hover
    
    init() {
        // Prefetch navigation links on hover
        const navLinks = document.querySelectorAll('.nav-link[href]');
        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
                // Prefetch on hover with small delay
                let prefetchTimeout;
                link.addEventListener('mouseenter', () => {
                    prefetchTimeout = setTimeout(() => {
                        this.prefetch(href);
                    }, this._prefetchDelay);
                });
                link.addEventListener('mouseleave', () => {
                    if (prefetchTimeout) {
                        clearTimeout(prefetchTimeout);
                    }
                });
            }
        });
        
        // Prefetch on touchstart for mobile (immediate)
        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
                link.addEventListener('touchstart', () => {
                    this.prefetch(href);
                }, { passive: true });
            }
        });
    },
    
    prefetch(url) {
        // Skip if already prefetched or if it's the current page
        if (this._prefetched.has(url) || url === window.location.pathname) {
            return;
        }
        
        // Create prefetch link
        const link = document.createElement('link');
        link.rel = 'prefetch';
        link.href = url;
        link.as = 'document';
        document.head.appendChild(link);
        
        this._prefetched.add(url);
    }
};

// ============================================
// PAGE TRANSITION OPTIMIZATION
// ============================================

const PageTransition = {
    init() {
        // Add transition class to body for smooth page changes
        document.body.classList.add('page-loaded');
        
        // Optimize link clicks for faster navigation
        document.addEventListener('click', (e) => {
            const link = e.target.closest('a[href]');
            if (link && !link.target && !link.hasAttribute('download') && 
                !link.href.startsWith('javascript:') && !link.href.startsWith('#')) {
                // Add loading state
                document.body.classList.add('page-navigating');
                
                // Remove the class if navigation doesn't happen (e.g., preventDefault was called)
                // Also remove it after a timeout to prevent it from staying active
                setTimeout(() => {
                    if (document.body.classList.contains('page-navigating')) {
                        document.body.classList.remove('page-navigating');
                    }
                }, 100);
            }
        }, true);
        
        // Remove page-navigating class when page is fully loaded
        window.addEventListener('load', () => {
            document.body.classList.remove('page-navigating');
        });
        
        // Remove page-navigating class if user navigates back/forward
        window.addEventListener('pageshow', (e) => {
            if (e.persisted) {
                document.body.classList.remove('page-navigating');
            }
        });
    }
};

// Invalidate cache on modification actions
document.addEventListener('DOMContentLoaded', () => {
    // Initialize prefetching
    LinkPrefetcher.init();
    
    // Initialize page transitions
    PageTransition.init();
    
    console.log('CTI Platform initialized');
});
