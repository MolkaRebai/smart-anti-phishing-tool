// Content script - runs on every page
class PageAnalyzer {
    constructor() {
        this.analyzeCurrentPage();
    }

    analyzeCurrentPage() {
        // Analyze links on the current page
        this.analyzeLinks();
        
        // Monitor for dynamically added links
        this.observePageChanges();
    }

    analyzeLinks() {
        const links = document.getElementsByTagName('a');
        const linkResults = [];
        
        for (let link of links) {
            if (link.href) {
                this.checkLinkSafety(link).then(safe => {
                    if (!safe) {
                        this.markSuspiciousLink(link);
                    }
                });
            }
        }
        
        return linkResults;
    }

    async checkLinkSafety(linkElement) {
        try {
            // Send message to background script to check URL
            const response = await new Promise((resolve) => {
                chrome.runtime.sendMessage({
                    action: 'checkUrl',
                    url: linkElement.href
                }, resolve);
            });
            
            return !response.isMalicious;
        } catch (error) {
            console.error('Error checking link safety:', error);
            return true; // Default to safe if error
        }
    }

    markSuspiciousLink(linkElement) {
        // Add visual indicator for suspicious links
        linkElement.style.border = '2px solid #ff4444';
        linkElement.style.position = 'relative';
        
        // Add warning tooltip
        linkElement.title = '⚠️ This link appears suspicious. Proceed with caution.';
        
        // Add click warning
        linkElement.addEventListener('click', (e) => {
            if (!confirm('⚠️ Warning: This link has been flagged as potentially malicious. Are you sure you want to proceed?')) {
                e.preventDefault();
                e.stopPropagation();
            }
        });
    }

    observePageChanges() {
        // Watch for dynamically added content
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        if (node.tagName === 'A' && node.href) {
                            this.checkLinkSafety(node).then(safe => {
                                if (!safe) this.markSuspiciousLink(node);
                            });
                        } else {
                            // Check for links in added nodes
                            const links = node.getElementsByTagName?.('a') || [];
                            for (let link of links) {
                                this.checkLinkSafety(link).then(safe => {
                                    if (!safe) this.markSuspiciousLink(link);
                                });
                            }
                        }
                    }
                });
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new PageAnalyzer());
} else {
    new PageAnalyzer();
}