// Content Script for Real-time URL Detection
class PhishingDetector {
  constructor() {
    this.detectedUrls = new Map();
    this.isScanning = false;
    this.init();
  }

  init() {
    this.injectStyles();
    this.setupMutationObserver();
    this.scanPage();
    
    // Listen for messages from background/popup
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      switch (request.action) {
        case "scanAllUrls":
          this.scanPage(true);
          break;
        case "showNavigationWarning":
          this.showNavigationWarning(request.data);
          break;
        case "autoScan":
          this.scanPage();
          break;
      }
    });
  }

  injectStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .phishing-highlight {
        background-color: #ff4444 !important;
        color: white !important;
        padding: 2px 4px !important;
        border-radius: 3px !important;
        border: 2px solid #ff0000 !important;
        cursor: pointer !important;
        position: relative !important;
        font-weight: bold !important;
        text-decoration: underline wavy red !important;
      }
      
      .phishing-warning-floating {
        position: fixed;
        top: 20px;
        right: 20px;
        background: #ff4444;
        color: white;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 10000;
        max-width: 300px;
        font-family: Arial, sans-serif;
        font-size: 14px;
        animation: slideInRight 0.3s ease-out;
      }
      
      @keyframes slideInRight {
        from {
          transform: translateX(100%);
          opacity: 0;
        }
        to {
          transform: translateX(0);
          opacity: 1;
        }
      }
    `;
    document.head.appendChild(style);
  }

  extractUrls(text) {
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
    return text.match(urlRegex) || [];
  }

  async scanPage(force = false) {
    if (this.isScanning && !force) return;
    this.isScanning = true;

    const textNodes = this.getAllTextNodes();
    const foundUrls = new Set();

    textNodes.forEach(node => {
      const urls = this.extractUrls(node.textContent);
      urls.forEach(url => foundUrls.add(url));
    });

    // Also check all anchor tags
    document.querySelectorAll('a[href]').forEach(link => {
      const href = link.getAttribute('href');
      if (href && href.startsWith('http')) {
        foundUrls.add(href);
      }
    });

    for (const url of foundUrls) {
      if (!this.detectedUrls.has(url)) {
        await this.analyzeAndHighlightUrl(url);
      }
    }

    this.isScanning = false;
  }

  getAllTextNodes() {
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    const textNodes = [];
    let node;
    while (node = walker.nextNode()) {
      if (node.textContent.trim().length > 0) {
        textNodes.push(node);
      }
    }
    return textNodes;
  }

  async analyzeAndHighlightUrl(url) {
    try {
      const response = await chrome.runtime.sendMessage({
        action: "analyzeUrl",
        url: url
      });

      if (response && response.is_phishing && !response.error) {
        this.detectedUrls.set(url, response);
        this.highlightUrl(url, response);
      }
    } catch (error) {
      console.error('Error analyzing URL:', error);
    }
  }

  highlightUrl(url, result) {
    // Highlight in text content
    this.highlightTextUrls(url, result);
    
    // Highlight in links
    this.highlightLinkUrls(url, result);
    
    // Show floating warning for high-confidence phishing
    if (result.confidence > 0.7) {
      this.showFloatingWarning(url, result);
    }
  }

  highlightTextUrls(url, result) {
    const elements = document.querySelectorAll('*:not(script):not(style)');
    
    elements.forEach(element => {
      if (element.textContent.includes(url) && !element.classList.contains('phishing-highlighted')) {
        const html = element.innerHTML;
        const highlightedHtml = html.replace(
          new RegExp(url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'),
          `<span class="phishing-highlight" title="Phishing detected - ${(result.confidence * 100).toFixed(1)}% confidence">${url}</span>`
        );
        
        if (html !== highlightedHtml) {
          element.innerHTML = highlightedHtml;
          element.classList.add('phishing-highlighted');
        }
      }
    });
  }

  highlightLinkUrls(url, result) {
    document.querySelectorAll(`a[href="${url}"]`).forEach(link => {
      if (!link.classList.contains('phishing-highlighted')) {
        link.classList.add('phishing-highlight');
        link.style.cssText += '; background-color: #ff4444 !important; color: white !important; border: 2px solid red !important;';
        
        link.addEventListener('click', (e) => {
          e.preventDefault();
          this.showWarningModal(url, result);
        });
      }
    });
  }

  showFloatingWarning(url, result) {
    const warning = document.createElement('div');
    warning.className = 'phishing-warning-floating';
    warning.innerHTML = `
      <strong>⚠ Phishing Warning</strong>
      <p>Suspicious URL detected on this page</p>
      <p>Confidence: ${(result.confidence * 100).toFixed(1)}%</p>
      <button onclick="this.parentElement.remove()" style="
        background: white;
        color: #ff4444;
        border: none;
        padding: 5px 10px;
        border-radius: 4px;
        cursor: pointer;
        margin-top: 5px;
      ">Dismiss</button>
    `;
    
    document.body.appendChild(warning);
    
    setTimeout(() => {
      if (warning.parentElement) {
        warning.remove();
      }
    }, 10000);
  }

  showNavigationWarning(result) {
    this.showWarningModal(result.url, result);
  }

  showWarningModal(url, result) {
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.8);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 100000;
      font-family: Arial, sans-serif;
    `;
    
    modal.innerHTML = `
      <div style="
        background: white;
        padding: 30px;
        border-radius: 12px;
        max-width: 400px;
        text-align: center;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      ">
        <div style="font-size: 48px; color: #ff4444; margin-bottom: 15px;">⚠</div>
        <h2 style="color: #333; margin-bottom: 15px;">Phishing Warning</h2>
        <p style="color: #666; margin-bottom: 20px; line-height: 1.5;">
          This link appears to be a phishing attempt with 
          <strong>${(result.confidence * 100).toFixed(1)}% confidence</strong>.
        </p>
        <p style="color: #999; font-size: 12px; margin-bottom: 20px; word-break: break-all;">
          ${url}
        </p>
        <div style="display: flex; gap: 10px; justify-content: center;">
          <button id="phishing-proceed" style="
            background: #ff4444;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
          ">Proceed Anyway</button>
          <button id="phishing-cancel" style="
            background: #666;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
          ">Stay Safe</button>
        </div>
      </div>
    `;
    
    document.body.appendChild(modal);
    
    modal.querySelector('#phishing-proceed').addEventListener('click', () => {
      modal.remove();
      window.open(url, '_blank');
    });
    
    modal.querySelector('#phishing-cancel').addEventListener('click', () => {
      modal.remove();
    });
    
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
  }

  setupMutationObserver() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length) {
          setTimeout(() => this.scanPage(), 500);
        }
      });
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
}

// Initialize the detector when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new PhishingDetector();
  });
} else {
  new PhishingDetector();
}