/**
 * JavaScript for deepdarkcti page
 * Handles interactivity, refresh with progress, and link confirmation
 */

// IMPORTANT: No automatic download on page load
// Download only occurs when user explicitly clicks "Download" or "Refresh" buttons
document.addEventListener('DOMContentLoaded', function() {
    const refreshBtn = document.getElementById('refreshBtn');
    const downloadBtn = document.getElementById('downloadBtn');
    const searchBox = document.getElementById('searchBox');
    const categoriesContainer = document.getElementById('categoriesContainer');
    const categoryCards = document.querySelectorAll('.category-card');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const progressMessage = document.getElementById('progressMessage');
    const progressPercentage = document.getElementById('progressPercentage');
    
    // Confirmation modal (functions are in cti_resources_common.js)
    const linkModal = document.getElementById('linkModal');
    const copyLinkBtn = document.getElementById('copyLinkBtn');
    const openLinkBtn = document.getElementById('openLinkBtn');
    const cancelLinkBtn = document.getElementById('cancelLinkBtn');
    
    // Download button management
    if (downloadBtn) {
        downloadBtn.addEventListener('click', handleDownload);
    }
    
    // Refresh button management
    if (refreshBtn) {
        refreshBtn.addEventListener('click', handleRefresh);
    }
    
    // Manual source addition form management
    const addManualSourceForm = document.getElementById('addManualSourceForm');
    if (addManualSourceForm) {
        addManualSourceForm.addEventListener('submit', handleAddManualSource);
    }
    
    // Search management
    if (searchBox) {
        searchBox.addEventListener('input', handleSearch);
    }
    
    // Category card click management (expand/collapse with accordion)
    // Allow clicking on entire card, not just header
    categoryCards.forEach(card => {
        card.addEventListener('click', function(e) {
            // Don't toggle if clicking on a link, filter button, or delete button
            if (e.target.tagName === 'A' || 
                e.target.tagName === 'BUTTON' || 
                e.target.closest('button') ||
                e.target.closest('.source-delete-btn') ||
                e.target.closest('.filter-button')) {
                return;
            }
            
            const isExpanded = card.classList.contains('expanded');
            
            // Close all other cards (accordion)
            categoryCards.forEach(otherCard => {
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
    
    // Status filter management in each category (with exclusion)
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('filter-button')) {
            const filterBtn = e.target;
            const categoryCard = filterBtn.closest('.category-card');
            if (!categoryCard) return;
            
            const filterValue = filterBtn.getAttribute('data-filter');
            const action = filterBtn.getAttribute('data-action') || 'toggle';
            const sourceItems = categoryCard.querySelectorAll('.source-item');
            const allFilterBtns = categoryCard.querySelectorAll('.filter-button');
            
            // If it's "All", reset all filters
            if (filterValue === 'all') {
                allFilterBtns.forEach(btn => {
                    btn.classList.remove('active', 'excluded');
                });
                filterBtn.classList.add('active');
                
                // Show all sources
                sourceItems.forEach(item => {
                    item.style.display = '';
                });
                return;
            }
            
            // Filter toggle (include/exclude)
            if (action === 'toggle') {
                if (filterBtn.classList.contains('active')) {
                    // Passer en mode exclu
                    filterBtn.classList.remove('active');
                    filterBtn.classList.add('excluded');
                } else if (filterBtn.classList.contains('excluded')) {
                    // Remove exclusion
                    filterBtn.classList.remove('excluded');
                } else {
                    // Activate filter
                    filterBtn.classList.add('active');
                }
            }
            
            // Apply filters
            applyFiltersToCategory(categoryCard);
        }
        
        // Favorite button management
        if (e.target.classList.contains('source-favorite-btn') || e.target.closest('.source-favorite-btn')) {
            e.stopPropagation(); // Prevent card open/close
            const favoriteBtn = e.target.classList.contains('source-favorite-btn') ? e.target : e.target.closest('.source-favorite-btn');
            const sourceItem = favoriteBtn.closest('.source-item');
            if (sourceItem) {
                const sourceUrl = sourceItem.getAttribute('data-source-url');
                
                if (sourceUrl) {
                    fetch('/api/cti-resources/favorite/toggle', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            url: sourceUrl
                        })
                    }).then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            const isFavorite = data.is_favorite;
                            
                            // Update button
                            if (isFavorite) {
                                favoriteBtn.classList.add('active');
                                favoriteBtn.innerHTML = '⭐';
                                favoriteBtn.title = 'Remove from favorites';
                                
                                // Add indicator in name
                                const sourceName = sourceItem.querySelector('.source-name');
                                if (sourceName && !sourceName.querySelector('.favorite-indicator')) {
                                    const indicator = document.createElement('span');
                                    indicator.className = 'favorite-indicator';
                                    indicator.textContent = '⭐ ';
                                    sourceName.insertBefore(indicator, sourceName.firstChild);
                                }
                                
                                // Add favorite-source class
                                sourceItem.classList.add('favorite-source');
                                showNotification('Added to favorites', 'success');
                            } else {
                                favoriteBtn.classList.remove('active');
                                favoriteBtn.innerHTML = '☆';
                                favoriteBtn.title = 'Add to favorites';
                                
                                // Remove indicator from name
                                const indicator = sourceItem.querySelector('.favorite-indicator');
                                if (indicator) {
                                    indicator.remove();
                                }
                                
                                // Remove favorite-source class
                                sourceItem.classList.remove('favorite-source');
                                showNotification('Removed from favorites', 'success');
                            }
                        } else {
                            showNotification('Error: ' + data.message, 'error');
                        }
                    })
                    .catch(error => {
                        console.error('Error toggling favorite:', error);
                        showNotification('Error updating favorite', 'error');
                    });
                }
            }
            return;
        }
        
        // Source delete button management
        if (e.target.classList.contains('source-delete-btn') || e.target.closest('.source-delete-btn')) {
            e.stopPropagation(); // Prevent card open/close
            const deleteBtn = e.target.classList.contains('source-delete-btn') ? e.target : e.target.closest('.source-delete-btn');
            const sourceItem = deleteBtn.closest('.source-item');
            if (sourceItem) {
                const sourceUrl = sourceItem.getAttribute('data-source-url');
                const category = sourceItem.getAttribute('data-category');
                const isManual = sourceItem.getAttribute('data-is-manual') === 'true';
                
                // Disappearance animation
                sourceItem.style.transition = 'opacity 0.3s ease, transform 0.3s ease, max-height 0.3s ease, margin 0.3s ease, padding 0.3s ease';
                sourceItem.style.opacity = '0';
                sourceItem.style.transform = 'translateX(-20px) scale(0.95)';
                sourceItem.style.maxHeight = sourceItem.offsetHeight + 'px';
                
                // Send delete request to server
                if (sourceUrl) {
                    fetch('/api/cti-resources/source/delete', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            category: category || '_manual_sources',
                            url: sourceUrl,
                            is_manual: isManual
                        })
                    }).then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            console.log('Source deleted successfully');
                            if (isManual) {
                                showNotification('Manual source deleted successfully', 'success');
                            }
                        } else {
                            console.error('Error deleting:', data.message);
                            showNotification('Error deleting: ' + data.message, 'error');
                            // Restore display on error
                            sourceItem.style.opacity = '1';
                            sourceItem.style.transform = '';
                        }
                    })
                    .catch(error => {
                        console.error('Error deleting:', error);
                        showNotification('Error deleting', 'error');
                        // Restore display on error
                        sourceItem.style.opacity = '1';
                        sourceItem.style.transform = '';
                    });
                }
                
                setTimeout(() => {
                    // Completely remove element from DOM
                    sourceItem.remove();
                    
                    // Update category source count
                    const categoryCard = sourceItem.closest('.category-card');
                    if (categoryCard) {
                        const categoryCount = categoryCard.querySelector('.category-count');
                        if (categoryCount) {
                            const remainingSources = categoryCard.querySelectorAll('.source-item').length;
                            categoryCount.textContent = `${remainingSources} source${remainingSources > 1 ? 's' : ''}`;
                        }
                    }
                }, 300);
            }
        }
    });
    
    /**
     * Applies filters to a category
     */
    function applyFiltersToCategory(categoryCard) {
        const sourceItems = categoryCard.querySelectorAll('.source-item');
        const filterBtns = categoryCard.querySelectorAll('.filter-button');
        
        // Get activated and excluded statuses
        const includedStatuses = [];
        const excludedStatuses = [];
        
        filterBtns.forEach(btn => {
            const filterValue = btn.getAttribute('data-filter');
            if (filterValue === 'all') return;
            
            if (btn.classList.contains('active')) {
                includedStatuses.push(filterValue);
            } else if (btn.classList.contains('excluded')) {
                excludedStatuses.push(filterValue);
            }
        });
        
        // Apply filters
        sourceItems.forEach(item => {
            const itemStatus = item.getAttribute('data-source-status') || '';
            
            // If statuses are excluded, check first
            if (excludedStatuses.length > 0) {
                if (excludedStatuses.includes(itemStatus)) {
                    item.style.display = 'none';
                    return;
                }
            }
            
            // If statuses are included, check
            if (includedStatuses.length > 0) {
                if (includedStatuses.includes(itemStatus)) {
                    item.style.display = '';
                } else {
                    item.style.display = 'none';
                }
            } else {
                // If no included filters, show all except excluded
                item.style.display = '';
            }
        });
    }
    
    // Intercept clicks on source links
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('source-name')) {
            e.preventDefault();
            const url = e.target.getAttribute('href');
            showLinkModal(url, e); // Function from cti_resources_common.js
        }
    });
    
    // Modal management (functions are in cti_resources_common.js)
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
                hideLinkModal(); // Function from cti_resources_common.js
            }
        });
    }
    
    /**
     * Handles repository download
     */
    async function handleDownload() {
        // Inform user that internet connection is required
        if (!confirm('🌐 This action requires an internet connection.\n\n' +
                     'The download will connect to GitHub to retrieve the DeepDarkCTI repository.\n\n' +
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
            const response = await fetch('/api/cti-resources/download', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const data = await response.json();
            
            if (data.success) {
                updateProgress(100, 'Download completed!'); // Function from cti_resources_common.js
                showNotification('Repository downloaded successfully!', 'success'); // Function from cti_resources_common.js
                
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
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
     * Handles manual source addition
     */
    async function handleAddManualSource(e) {
        e.preventDefault();
        
        const urlInput = document.getElementById('manualSourceUrl');
        const nameInput = document.getElementById('manualSourceName');
        const descriptionInput = document.getElementById('manualSourceDescription');
        
        const url = urlInput.value.trim();
        const name = nameInput.value.trim() || null;
        const description = descriptionInput.value.trim() || null;
        
        if (!url) {
            showNotification('Please enter a URL', 'error');
            return;
        }
        
        // Disable form
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.textContent = 'Adding...';
        
        try {
            const response = await fetch('/api/cti-resources/manual-source/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    url: url,
                    name: name,
                    description: description
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showNotification('Source added successfully!', 'success');
                // Reset form
                urlInput.value = '';
                nameInput.value = '';
                descriptionInput.value = '';
                // Reload page to display new source
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else {
                throw new Error(data.message || 'Add error');
            }
        } catch (error) {
            console.error('Add error:', error);
            showNotification('Add error: ' + error.message, 'error');
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    }
    
    /**
     * Handles repository refresh
     */
    async function handleRefresh() {
        // Inform user that internet connection is required
        if (!confirm('🌐 This action requires an internet connection.\n\n' +
                     'The update will connect to GitHub to download the latest version of the DeepDarkCTI repository.\n\n' +
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
            const response = await fetch('/api/cti-resources/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const data = await response.json();
            
            if (data.success) {
                updateProgress(100, 'Update completed!'); // Function from cti_resources_common.js
                showNotification('Repository updated successfully!', 'success'); // Function from cti_resources_common.js
                
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
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
     * Resets refresh button
     */
    function resetRefreshButton() {
        const button = refreshBtn;
        const buttonText = button.querySelector('.button-text');
        button.classList.remove('loading');
        button.disabled = false;
        buttonText.textContent = '🔄 Update';
        
        if (progressContainer) {
            progressContainer.classList.remove('active');
        }
    }
    
    /**
     * Handles search in categories and sources
     */
    function handleSearch() {
        const searchTerm = searchBox.value.toLowerCase().trim();
        
        if (!searchTerm) {
            // Show all categories
            categoryCards.forEach(card => {
                card.style.display = '';
                // Reset source display
                const sources = card.querySelectorAll('.source-item');
                sources.forEach(source => {
                    source.style.display = '';
                });
            });
            return;
        }
        
        // Filter categories and sources
        categoryCards.forEach(card => {
            const categoryName = card.getAttribute('data-name') || '';
            const sources = card.querySelectorAll('.source-item');
            let hasMatch = categoryName.includes(searchTerm);
            
            // Check sources
            sources.forEach(source => {
                const sourceName = source.getAttribute('data-source-name') || '';
                const sourceText = source.textContent.toLowerCase();
                
                if (sourceName.includes(searchTerm) || sourceText.includes(searchTerm)) {
                    hasMatch = true;
                    source.style.display = '';
                } else {
                    source.style.display = 'none';
                }
            });
            
            // Show or hide category
            if (hasMatch) {
                card.style.display = '';
                // Auto-expand si une recherche est active
                if (!card.classList.contains('expanded')) {
                    card.classList.add('expanded');
                }
            } else {
                card.style.display = 'none';
            }
        });
    }
    
    // Card appearance animation on load
    if (categoryCards.length > 0) {
        categoryCards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            
            setTimeout(() => {
                card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 50);
        });
    }
});
