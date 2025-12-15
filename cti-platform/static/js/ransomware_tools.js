/**
 * JavaScript for Ransomware Tool Matrix page
 * Handles interactivity, refresh with progress, search, and section navigation
 */

// IMPORTANT: No automatic download on page load
// Download only occurs when user explicitly clicks "Download" or "Update" buttons
document.addEventListener('DOMContentLoaded', function() {
    const refreshBtn = document.getElementById('refreshBtn');
    const downloadBtn = document.getElementById('downloadBtn');
    const searchBox = document.getElementById('searchBox');
    const sectionTabs = document.querySelectorAll('.section-tab');
    const toolCards = document.querySelectorAll('.tool-card, .threat-intel-card, .profile-card, .report-card');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const progressMessage = document.getElementById('progressMessage');
    const progressPercentage = document.getElementById('progressPercentage');
    
    let currentSection = 'tools';
    
    // Download button management
    if (downloadBtn) {
        downloadBtn.addEventListener('click', handleDownload);
    }
    
    // Refresh button management
    if (refreshBtn) {
        refreshBtn.addEventListener('click', handleRefresh);
    }
    
    // Search management
    if (searchBox) {
        searchBox.addEventListener('input', handleSearch);
    }
    
    // Section tab management
    sectionTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const section = this.getAttribute('data-section');
            switchSection(section);
        });
    });
    
    // Link confirmation modal elements (functions are in cti_resources_common.js)
    const linkModal = document.getElementById('linkModal');
    const copyLinkBtn = document.getElementById('copyLinkBtn');
    const openLinkBtn = document.getElementById('openLinkBtn');
    const cancelLinkBtn = document.getElementById('cancelLinkBtn');
    
    // Modal management
    if (copyLinkBtn) {
        copyLinkBtn.addEventListener('click', handleCopyLink);
    }
    if (openLinkBtn) {
        openLinkBtn.addEventListener('click', handleOpenLink);
    }
    if (cancelLinkBtn) {
        cancelLinkBtn.addEventListener('click', hideLinkModal);
    }
    
    // Close modal by clicking on overlay
    if (linkModal) {
        linkModal.addEventListener('click', function(e) {
            if (e.target === linkModal) {
                hideLinkModal();
            }
        });
    }
    
    // Intercept clicks on external links (functions are in cti_resources_common.js)
    document.addEventListener('click', function(e) {
        const link = e.target.closest('a.external-link');
        if (link && link.target === '_blank') {
            e.preventDefault();
            e.stopPropagation();
            const url = link.getAttribute('href');
            if (url) {
                showLinkModal(url, e); // Function from cti_resources_common.js
            }
        }
        
        // Also intercept clicks on regular links in threat intel and profiles
        if (e.target.tagName === 'A' && e.target.target === '_blank' &&
            (e.target.closest('.threat-group-item') || e.target.closest('.profile-card'))) {
            const url = e.target.getAttribute('href');
            if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
                e.preventDefault();
                showLinkModal(url, e); // Function from cti_resources_common.js
            }
        }
    });
    
    // Card click management (expand/collapse)
    toolCards.forEach(card => {
        card.addEventListener('click', function(e) {
            // Don't toggle if clicking on a link or button
            if (e.target.tagName === 'A' || 
                e.target.tagName === 'BUTTON' || 
                e.target.closest('button') ||
                e.target.closest('a') ||
                e.target.classList.contains('copy-link-btn')) {
                return;
            }
            
            const isExpanded = card.classList.contains('expanded');
            
            // Close all other cards in the same section
            const sectionCards = document.querySelectorAll(`#${currentSection}Section .tool-card, #${currentSection}Section .threat-intel-card, #${currentSection}Section .profile-card, #${currentSection}Section .report-card`);
            sectionCards.forEach(otherCard => {
                if (otherCard !== card) {
                    otherCard.classList.remove('expanded');
                }
            });
            
            // Toggle clicked card
            if (isExpanded) {
                card.classList.remove('expanded');
            } else {
                card.classList.add('expanded');
            }
        });
    });
    
    /**
     * Switches between sections
     */
    function switchSection(section) {
        currentSection = section;
        
        // Update tabs
        sectionTabs.forEach(tab => {
            if (tab.getAttribute('data-section') === section) {
                tab.classList.add('active');
            } else {
                tab.classList.remove('active');
            }
        });
        
        // Update content - map section names to actual IDs
        const sectionMap = {
            'tools': 'toolsSection',
            'threat-intel': 'threatIntelSection',
            'profiles': 'profilesSection',
            'reports': 'reportsSection'
        };
        
        Object.keys(sectionMap).forEach(sec => {
            const sectionId = sectionMap[sec];
            const sectionEl = document.getElementById(sectionId);
            if (sectionEl) {
                if (sec === section) {
                    sectionEl.classList.add('active');
                } else {
                    sectionEl.classList.remove('active');
                }
            }
        });
        
        // Clear search when switching sections
        if (searchBox) {
            searchBox.value = '';
            handleSearch();
        }
    }
    
    /**
     * Handles repository download
     */
    async function handleDownload() {
        // Inform user that internet connection is required
        if (!confirm('🌐 This action requires an internet connection.\n\n' +
                     'The download will connect to GitHub to retrieve the Ransomware Tool Matrix repository.\n\n' +
                     'Do you want to continue?')) {
            return;
        }
        
        const button = downloadBtn;
        const buttonText = button.querySelector('.button-text');
        const originalText = buttonText.textContent;
        
        button.classList.add('loading');
        button.disabled = true;
        buttonText.textContent = 'Downloading...';
        
        if (progressContainer) {
            progressContainer.classList.add('active');
            updateProgress(10, 'Downloading repository from GitHub...'); // Function from cti_resources_common.js
        }
        
        try {
            const response = await fetch('/api/ransomware-tools/download', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const data = await response.json();
            
            if (data.success) {
                updateProgress(100, 'Download completed!'); // Function from cti_resources_common.js
                showNotification('Repository downloaded successfully! Reloading page...', 'success'); // Function from cti_resources_common.js
                
                // Force a hard reload to ensure fresh data is loaded
                setTimeout(() => {
                    window.location.href = window.location.href.split('?')[0];
                }, 1500);
            } else {
                throw new Error(data.message || 'Download error');
            }
        } catch (error) {
            console.error('Download error:', error);
            let errorMessage = 'Download error: ' + error.message;
            if (error.message.includes('fetch') || error.message.includes('network')) {
                errorMessage += '\n\nPlease check your internet connection.';
            }
            showNotification(errorMessage, 'error');
            
            button.classList.remove('loading');
            button.disabled = false;
            buttonText.textContent = originalText;
            
            if (progressContainer) {
                progressContainer.classList.remove('active');
            }
        }
    }
    
    /**
     * Handles repository refresh
     */
    async function handleRefresh() {
        // Inform user that internet connection is required
        if (!confirm('🌐 This action requires an internet connection.\n\n' +
                     'The update will connect to GitHub to download the latest version of the Ransomware Tool Matrix repository.\n\n' +
                     'Do you want to continue?')) {
            return;
        }
        
        const button = refreshBtn;
        const buttonText = button.querySelector('.button-text');
        const originalText = buttonText.textContent;
        
        button.classList.add('loading');
        button.disabled = true;
        buttonText.textContent = 'Refreshing...';
        
        if (progressContainer) {
            progressContainer.classList.add('active');
            updateProgress(10, 'Updating repository from GitHub...'); // Function from cti_resources_common.js
        }
        
        try {
            const response = await fetch('/api/ransomware-tools/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const data = await response.json();
            
            if (data.success) {
                updateProgress(100, 'Update completed!'); // Function from cti_resources_common.js
                showNotification('Repository updated successfully! Reloading page...', 'success'); // Function from cti_resources_common.js
                
                // Force a hard reload to ensure fresh data is loaded
                setTimeout(() => {
                    window.location.href = window.location.href.split('?')[0];
                }, 1500);
            } else {
                throw new Error(data.message || 'Update error');
            }
        } catch (error) {
            console.error('Update error:', error);
            let errorMessage = 'Update error: ' + error.message;
            if (error.message.includes('fetch') || error.message.includes('network')) {
                errorMessage += '\n\nPlease check your internet connection.';
            }
            showNotification(errorMessage, 'error');
            
            button.classList.remove('loading');
            button.disabled = false;
            buttonText.textContent = originalText;
            
            if (progressContainer) {
                progressContainer.classList.remove('active');
            }
        }
    }
    
    /**
     * Handles search (optimized with debouncing)
     */
    let searchTimeout;
    function handleSearch() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            const query = searchBox.value.toLowerCase().trim();
            
            // Get current section cards
            const sectionId = `${currentSection}Section`;
            const sectionEl = document.getElementById(sectionId);
            if (!sectionEl) return;
            
            const cards = sectionEl.querySelectorAll('.tool-card, .threat-intel-card, .profile-card, .report-card');
            
            // Use requestAnimationFrame for smooth rendering
            requestAnimationFrame(() => {
                cards.forEach(card => {
                    const cardText = card.textContent.toLowerCase();
                    const matches = query === '' || cardText.includes(query);
                    
                    if (matches) {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }
                });
            });
        }, 150); // Debounce search by 150ms
    }
    
    // Optimize scroll performance
    let scrollTimeout;
    let isScrolling = false;
    
    function handleScroll() {
        if (!isScrolling) {
            isScrolling = true;
            // Add a class to body during scroll for CSS optimizations
            document.body.classList.add('is-scrolling');
        }
        
        clearTimeout(scrollTimeout);
        scrollTimeout = setTimeout(() => {
            isScrolling = false;
            document.body.classList.remove('is-scrolling');
        }, 150);
    }
    
    // Throttled scroll handler using requestAnimationFrame
    let scrollRafId = null;
    function optimizedScrollHandler() {
        if (scrollRafId === null) {
            scrollRafId = requestAnimationFrame(() => {
                handleScroll();
                scrollRafId = null;
            });
        }
    }
    
    // Add passive scroll listener for better performance
    window.addEventListener('scroll', optimizedScrollHandler, { passive: true });
    
});

