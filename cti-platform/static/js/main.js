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
    
    // Make request
    const response = await fetch(url, options);
    const data = await response.json();
    
    // Cache only if successful
    if (response.ok) {
        ClientCache.set(key, { response, data }, ttl);
    }
    
    return { response, data };
}

// Invalidate cache on modification actions
document.addEventListener('DOMContentLoaded', () => {
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

