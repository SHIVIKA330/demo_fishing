// Enhanced Background Script for Phishing Detection
let detectedUrls = new Map();

// Cloud backend URL - UPDATE THIS WITH YOUR RENDER URL AFTER DEPLOYMENT
const BACKEND_URL = 'https://phishing-detector-backend-r29g.onrender.com';

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Detector Pro Extension Installed');
  chrome.storage.local.set({
    phishingCount: 0,
    safeCount: 0,
    totalScans: 0,
    lastScan: null
  });
});

// Listen for URL analysis requests
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeUrl") {
    analyzeUrl(request.url).then(result => {
      sendResponse(result);
    }).catch(error => {
      console.error('Analysis error:', error);
      sendResponse({ 
        is_phishing: false, 
        error: true,
        message: 'Analysis failed',
        confidence: 0
      });
    });
    return true;
  }

  if (request.action === "scanPage") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "scanAllUrls" });
      }
    });
    sendResponse({ status: "scanning" });
    return true;
  }
});

// Enhanced URL analysis function with retry logic
async function analyzeUrl(url) {
  try {
    // Check cache first
    if (detectedUrls.has(url)) {
      const cached = detectedUrls.get(url);
      if (Date.now() - cached.timestamp < 300000) { // 5 minutes cache
        return cached.result;
      }
    }

    console.log('Analyzing URL:', url);
    
    const response = await fetchWithRetry(`${BACKEND_URL}/predict`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url })
    }, 2); // 2 retries

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    console.log('Analysis result:', data);
    
    // Cache the result
    detectedUrls.set(url, {
      result: data,
      timestamp: Date.now()
    });

    // Update statistics
    updateStatistics(data.is_phishing);

    return data;
  } catch (error) {
    console.error('Error analyzing URL:', error);
    return { 
      is_phishing: false, 
      error: true,
      message: 'Cloud service unavailable. Please try again later.',
      confidence: 0
    };
  }
}

// Fetch with retry for cold start issues
async function fetchWithRetry(url, options, retries = 2) {
  for (let i = 0; i <= retries; i++) {
    try {
      const response = await fetch(url, options);
      if (response.ok) return response;
      
      // If not OK but not server error, don't retry
      if (response.status < 500) {
        return response;
      }
    } catch (error) {
      console.log(`Attempt ${i + 1} failed:`, error);
    }
    
    // Wait before retry (exponential backoff)
    if (i < retries) {
      await new Promise(resolve => setTimeout(resolve, 2000 * (i + 1)));
    }
  }
  
  throw new Error(`Failed after ${retries + 1} attempts`);
}

// Update scan statistics
function updateStatistics(isPhishing) {
  chrome.storage.local.get(['phishingCount', 'safeCount', 'totalScans'], (result) => {
    const phishingCount = result.phishingCount || 0;
    const safeCount = result.safeCount || 0;
    const totalScans = result.totalScans || 0;

    const updates = {
      totalScans: totalScans + 1,
      lastScan: new Date().toISOString()
    };

    if (isPhishing) {
      updates.phishingCount = phishingCount + 1;
    } else {
      updates.safeCount = safeCount + 1;
    }

    chrome.storage.local.set(updates);
  });
}
