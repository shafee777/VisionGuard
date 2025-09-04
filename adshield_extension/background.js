// background.js
let scanTimer = null;
const SCAN_DEBOUNCE_MS = 700;

function log(...args) { console.log("[AdShield]", ...args); }

function scheduleScan() {
  if (scanTimer) clearTimeout(scanTimer);
  scanTimer = setTimeout(() => {
    scanActiveTab();
    scanTimer = null;
  }, SCAN_DEBOUNCE_MS);
}

function scanActiveTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) {
      log("No active tab found");
      chrome.storage.local.remove("adshield_result");
      return;
    }

    const tab = tabs[0];
    const url = tab && tab.url;
    log("Active tab URL:", url);

    // Only scan http/https pages
    if (!url || !(url.startsWith("http://") || url.startsWith("https://"))) {
      log("Skipping scan for invalid URL:", url);
      chrome.storage.local.remove("adshield_result");
      return;
    }

    // POST to Flask
    fetch("http://127.0.0.1:5000/api/detect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ad_url: url })
    })
      .then(async (res) => {
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          throw new Error("Flask error " + res.status + ": " + text);
        }
        return res.json();
      })
      .then((data) => {
        log("Flask response:", data);
        chrome.storage.local.set({ adshield_result: data }, () => {
          log("Saved adshield_result");
        });
      })
      .catch((err) => {
        console.error("[AdShield] Error contacting Flask:", err);
        chrome.storage.local.set({ adshield_result: { error: err.message } });
      });
  });
}

// When user switches tab
chrome.tabs.onActivated.addListener(() => {
  chrome.storage.local.remove("adshield_result", () => {
    log("Cleared old scan result on tab switch");
    scheduleScan();
  });
});

// When tab updates finish (navigation complete)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab && tab.active) {
    chrome.storage.local.remove("adshield_result", () => {
      log("Cleared old scan result on tab update");
      scheduleScan();
    });
  }
});

// Optional: allow manual scan when user clicks icon (action)
chrome.action.onClicked.addListener((tab) => {
  log("Action clicked, scheduling scan");
  scheduleScan();
});
