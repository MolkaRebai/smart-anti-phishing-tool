document.addEventListener('DOMContentLoaded', async () => {
    await updatePopup();
    
    // Check current page safety
    document.getElementById('checkPage').addEventListener('click', checkCurrentPage);
    document.getElementById('viewLogs').addEventListener('click', viewBlockLog);
});

async function updatePopup() {
    try {
        // Get current tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab) {
            document.getElementById('currentUrl').textContent = tab.url;
            
            // Check URL safety
            const response = await chrome.runtime.sendMessage({
                action: 'checkUrl',
                url: tab.url
            });
            
            updateSafetyStatus(response);
        }
        
        // Get stats
        const stats = await chrome.runtime.sendMessage({ action: 'getStats' });
        document.getElementById('blockedCount').textContent = stats.totalBlocked;
        document.getElementById('modelStatus').textContent = stats.modelStatus;
        
    } catch (error) {
        console.error('Error updating popup:', error);
    }
}

function updateSafetyStatus(prediction) {
    const statusElement = document.getElementById('safetyStatus');
    const statusIndicator = document.getElementById('status');
    
    if (prediction.isMalicious) {
        statusElement.textContent = '🚨 MALICIOUS - This URL is blocked';
        statusElement.style.background = '#f8d7da';
        statusElement.style.color = '#721c24';
        statusIndicator.textContent = 'Danger';
        statusIndicator.className = 'status danger';
    } else {
        statusElement.textContent = '✅ SAFE - This URL appears legitimate';
        statusElement.style.background = '#d4edda';
        statusElement.style.color = '#155724';
        statusIndicator.textContent = 'Safe';
        statusIndicator.className = 'status safe';
    }
}

async function checkCurrentPage() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (tab) {
        // Send message to content script to analyze page
        chrome.tabs.sendMessage(tab.id, { action: 'analyzePage' });
        
        // Update popup
        await updatePopup();
    }
}

function viewBlockLog() {
    // Open options page or create a log viewer
    chrome.tabs.create({ url: chrome.runtime.getURL('blocked/#?view=log') });
}