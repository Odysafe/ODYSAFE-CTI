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

function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    
    // Insert at the beginning of main content
    const main = document.querySelector('.main-content');
    if (main) {
        main.insertBefore(alertDiv, main.firstChild);
        
        // Remove after 5 seconds
        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }
}

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

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
    }
}

// Close modals by clicking outside
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) {
        e.target.classList.remove('active');
    }
});

// ============================================
// FORM MANAGEMENT
// ============================================

function handleFormSubmit(formId, endpoint, method = 'POST', onSuccess = null) {
    const form = document.getElementById(formId);
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.textContent = 'Processing...';
        
        try {
            const formData = new FormData(form);
            let response;
            
            if (method === 'POST' && form.enctype === 'multipart/form-data') {
                response = await fetch(endpoint, {
                    method: 'POST',
                    body: formData
                });
            } else {
                const data = Object.fromEntries(formData);
                response = await fetch(endpoint, {
                    method: method,
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });
            }
            
            const result = await response.json();
            
            if (response.ok) {
                if (onSuccess) {
                    onSuccess(result);
                } else {
                    showAlert(result.message || 'Operation successful', 'success');
                }
            } else {
                showAlert(result.error || 'An error occurred', 'error');
            }
        } catch (error) {
            showAlert(`Error: ${error.message}`, 'error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    });
}

// ============================================
// CLIENT CACHE SYSTEM
// ============================================

const ClientCache = {
    _cache: new Map(),
    _defaultTTL: 60000, // 1 minute by default
    
    set(key, value, ttl = this._defaultTTL) {
        const expiry = Date.now() + ttl;
        this._cache.set(key, { value, expiry });
    },
    
    get(key) {
        const item = this._cache.get(key);
        if (!item) return null;
        
        if (Date.now() > item.expiry) {
            this._cache.delete(key);
            return null;
        }
        
        return item.value;
    },
    
    invalidate(pattern) {
        if (typeof pattern === 'string') {
            // Invalidate a specific key
            this._cache.delete(pattern);
        } else if (pattern instanceof RegExp) {
            // Invalidate all keys matching the pattern
            for (const key of this._cache.keys()) {
                if (pattern.test(key)) {
                    this._cache.delete(key);
                }
            }
        } else {
            // Invalidate entire cache
            this._cache.clear();
        }
    },
    
    clear() {
        this._cache.clear();
    }
};

// Helper function for fetch with cache
async function fetchWithCache(url, options = {}, cacheKey = null, ttl = 60000) {
    const key = cacheKey || url;
    
    // Check cache
    const cached = ClientCache.get(key);
    if (cached) {
        return cached;
    }
    
    // Make request with AbortController for better control
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout
    
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal,
            cache: 'default' // Allow browser caching
        });
        const data = await response.json();
        
        // Cache only if successful
        if (response.ok) {
            ClientCache.set(key, { response, data }, ttl);
        }
        
        clearTimeout(timeoutId);
        return { response, data };
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            throw new Error('Request timeout');
        }
        throw error;
    }
}

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
    
    // Listen to custom events to invalidate cache
    document.addEventListener('ioc-deleted', () => {
        ClientCache.invalidate(/\/api\/stats/);
        ClientCache.invalidate(/\/api\/iocs/);
    });
    
    document.addEventListener('source-deleted', () => {
        ClientCache.invalidate(/\/api\/stats/);
        ClientCache.invalidate(/\/api\/sources/);
    });
    
    document.addEventListener('ioc-updated', () => {
        ClientCache.invalidate(/\/api\/ioc\//);
    });
    
    console.log('CTI Platform initialized');
});

