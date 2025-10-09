document.addEventListener('DOMContentLoaded', function() {
  const elements = {
    scanButton: document.getElementById('scanPage'),
    checkCurrentButton: document.getElementById('checkCurrent'),
    viewHistoryButton: document.getElementById('viewHistory'),
    status: document.getElementById('status'),
    currentUrl: document.getElementById('currentUrl'),
    confidence: document.getElementById('confidence'),
    safeCount: document.getElementById('safeCount'),
    phishingCount: document.getElementById('phishingCount'),
    totalScans: document.getElementById('totalScans'),
    lastScan: document.getElementById('lastScan'),
    connectionStatus: document.getElementById('connectionStatus'),
    serviceStatus: document.getElementById('serviceStatus'),
    urlInfo: document.getElementById('urlInfo')
  };

  // Cloud backend URL - UPDATE THIS WITH YOUR RENDER URL AFTER DEPLOYMENT
  const BACKEND_URL = 'https://phishing-detector-backend.onrender.com';

  // Initialize
  loadStatistics();
  checkServiceStatus();
  autoScanCurrentPage();

  // Event Listeners
  elements.scanButton.addEventListener('click', scanCurrentPage);
  elements.checkCurrentButton.addEventListener('click', checkCurrentUrl);
  elements.viewHistoryButton.addEventListener('click', viewHistory);

  async function scanCurrentPage() {
    setStatus('scanning', '🔍 Scanning page for URLs...');
    
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      // Send message to content script to scan all URLs
      chrome.tabs.sendMessage(tab.id, { action: "scanAllUrls" }, (response) => {
        if (chrome.runtime.lastError) {
          console.log('Content script not ready:', chrome.runtime.lastError);
          setStatus('error', '❌ Please refresh the page and try again');
          return;
        }
        
        setStatus('scanning', '🔍 Scanning page content...');
        
        // Also check the current page URL
        setTimeout(() => {
          checkCurrentUrl();
        }, 1500);
      });
      
    } catch (error) {
      setStatus('error', '❌ Scan failed: ' + error.message);
      console.error('Scan error:', error);
    }
  }

  async function checkCurrentUrl() {
    setStatus('scanning', '🔍 Analyzing current page...');
    
    try {
      let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
        setStatus('error', '❌ Cannot scan Chrome pages');
        return;
      }
      
      const response = await chrome.runtime.sendMessage({
        action: "analyzeUrl",
        url: tab.url
      });

      updateUI(response, tab.url);
      updateStatistics();
      
    } catch (error) {
      setStatus('error', '❌ Analysis failed: ' + error.message);
      console.error('Analysis error:', error);
    }
  }

  function updateUI(result, url) {
    elements.currentUrl.textContent = shortenUrl(url);
    elements.urlInfo.style.display = 'block';
    
    if (result.error) {
      setStatus('error', '❌ ' + (result.message || 'Service unavailable'));
      elements.confidence.textContent = 'Cloud offline';
      elements.confidence.className = 'confidence error';
      
      // Show cloud connection status
      elements.serviceStatus.textContent = 'Offline - Cloud service';
      elements.connectionStatus.className = 'connection-status offline';
      
    } else if (result.is_phishing) {
      setStatus('warning', `🚨 Phishing detected!`);
      elements.confidence.textContent = `${(result.confidence * 100).toFixed(1)}% confidence`;
      elements.confidence.className = 'confidence warning';
      
    } else {
      setStatus('safe', '✅ This page is safe');
      elements.confidence.textContent = `${((1 - result.confidence) * 100).toFixed(1)}% safe`;
      elements.confidence.className = 'confidence safe';
    }
    
    elements.lastScan.textContent = new Date().toLocaleTimeString();
  }

  function setStatus(type, message) {
    elements.status.className = `status ${type}`;
    const statusText = elements.status.querySelector('.status-text');
    const statusIcon = elements.status.querySelector('.status-icon');
    
    if (statusText) statusText.textContent = message;
    if (statusIcon) {
      statusIcon.textContent = 
        type === 'safe' ? '✅' : 
        type === 'warning' ? '🚨' : 
        type === 'error' ? '❌' : '🔍';
    }
  }

  async function loadStatistics() {
    const result = await chrome.storage.local.get([
      'phishingCount', 
      'safeCount', 
      'totalScans', 
      'lastScan'
    ]);
    
    elements.safeCount.textContent = result.safeCount || 0;
    elements.phishingCount.textContent = result.phishingCount || 0;
    elements.totalScans.textContent = result.totalScans || 0;
    
    if (result.lastScan) {
      elements.lastScan.textContent = new Date(result.lastScan).toLocaleTimeString();
    }
  }

  async function updateStatistics() {
    setTimeout(loadStatistics, 500);
  }

  async function checkServiceStatus() {
    try {
      const testResponse = await fetch(`${BACKEND_URL}/test`);
      if (testResponse.ok) {
        const data = await testResponse.json();
        elements.serviceStatus.textContent = 'Connected (Cloud)';
        elements.connectionStatus.className = 'connection-status connected';
      } else {
        throw new Error('Server not responding');
      }
    } catch (error) {
      elements.serviceStatus.textContent = 'Offline - Cloud service';
      elements.connectionStatus.className = 'connection-status offline';
    }
  }

  function autoScanCurrentPage() {
    setTimeout(checkCurrentUrl, 300);
  }

  function viewHistory() {
    // Simple history view - could be enhanced
    alert(`Security Stats:\nSafe URLs: ${elements.safeCount.textContent}\nPhishing Detected: ${elements.phishingCount.textContent}\nTotal Scans: ${elements.totalScans.textContent}`);
  }

  function shortenUrl(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname + (urlObj.pathname !== '/' ? urlObj.pathname.substring(0, 15) + '...' : '');
    } catch {
      return url.substring(0, 25) + (url.length > 25 ? '...' : '');
    }
  }
});
