/**
 * Common JavaScript functions for CTI Resources pages
 * Shared between deepdarkcti.js and ransomware_tools.js
 */

// Global variables for link modal (will be initialized by each page)
let currentLinkUrl = null;

/**
 * Updates progress bar
 * @param {number} percentage - Progress percentage (0-100)
 * @param {string} message - Progress message
 */
function updateProgress(percentage, message) {
    const progressBar = document.getElementById('progressBar');
    const progressPercentage = document.getElementById('progressPercentage');
    const progressMessage = document.getElementById('progressMessage');
    
    if (progressBar) {
        progressBar.style.width = percentage + '%';
    }
    if (progressPercentage) {
        progressPercentage.textContent = Math.round(percentage) + '%';
    }
    if (progressMessage) {
        progressMessage.textContent = message;
    }
}

/**
 * Shows confirmation modal for a link
 * @param {string} url - URL to display in modal
 * @param {Event} event - Click event to position modal near clicked element
 */
function showLinkModal(url, event) {
    currentLinkUrl = url;
    const modalLinkUrl = document.getElementById('modalLinkUrl');
    const linkModal = document.getElementById('linkModal');
    const modalContent = linkModal ? linkModal.querySelector('.modal-content') : null;

    if (modalLinkUrl) {
        modalLinkUrl.textContent = url;
    }

    // Position modal near clicked element if event is provided
    if (event && modalContent) {
        const linkRect = event.target.getBoundingClientRect();
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        const modalWidth = 500; // Approximate modal width
        const modalHeight = 200; // Approximate modal height

        // Try to position to the right of the link first
        let left = linkRect.right + 10;
        let top = linkRect.top;

        // If not enough space to the right, try to the left
        if (left + modalWidth > viewportWidth) {
            left = linkRect.left - modalWidth - 10;
        }

        // If still not enough space, position below and align with left edge
        if (left < 0) {
            left = linkRect.left;
            top = linkRect.bottom + 10;
        }

        // If still not enough space below, position above
        if (top + modalHeight > viewportHeight) {
            top = linkRect.top - modalHeight - 10;
        }

        // Ensure modal stays within viewport bounds
        left = Math.max(10, Math.min(left, viewportWidth - modalWidth - 10));
        top = Math.max(10, Math.min(top, viewportHeight - modalHeight - 10));

        modalContent.style.top = top + 'px';
        modalContent.style.left = left + 'px';
        modalContent.style.right = 'auto';
    }

    if (linkModal) {
        linkModal.classList.add('active');

        // Automatically scroll to modal position
        setTimeout(() => {
            if (modalContent) {
                modalContent.scrollIntoView({
                    behavior: 'smooth',
                    block: 'center'
                });
            }
        }, 100);
    }
}

/**
 * Hides confirmation modal
 */
function hideLinkModal() {
    const linkModal = document.getElementById('linkModal');
    if (linkModal) {
        linkModal.classList.remove('active');
    }
    currentLinkUrl = null;
}

/**
 * Copies link to clipboard
 */
async function handleCopyLink() {
    if (!currentLinkUrl) return;
    
    try {
        await navigator.clipboard.writeText(currentLinkUrl);
        showNotification('Link copied to clipboard!', 'success');
        hideLinkModal();
    } catch (error) {
        console.error('Copy error:', error);
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = currentLinkUrl;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            showNotification('Link copied to clipboard!', 'success');
            hideLinkModal();
        } catch (err) {
            showNotification('Copy error', 'error');
        }
        document.body.removeChild(textArea);
    }
}

/**
 * Opens link in new tab
 */
function handleOpenLink() {
    if (currentLinkUrl) {
        window.open(currentLinkUrl, '_blank', 'noopener,noreferrer');
        hideLinkModal();
    }
}

/**
 * Shows a notification
 * @param {string} message - Notification message
 * @param {string} type - Notification type ('success' or 'error')
 */
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        padding: 16px 24px;
        background: ${type === 'success' ? 'rgba(34, 197, 94, 0.9)' : 'rgba(220, 38, 38, 0.9)'};
        color: white;
        border-radius: 12px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        z-index: 10000;
        font-weight: 500;
        animation: slideIn 0.3s ease;
        max-width: 400px;
    `;
    notification.textContent = message;
    
    // Add CSS animation if it doesn't exist yet
    if (!document.getElementById('notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            @keyframes slideIn {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            @keyframes slideOut {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(100%);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

