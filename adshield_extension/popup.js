document.addEventListener("DOMContentLoaded", () => {
  const resultDiv = document.getElementById("status");
  resultDiv.textContent = "Analyzing site...";

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.adshield_result) {
      showResult(changes.adshield_result.newValue);
    }
  });

  chrome.storage.local.get("adshield_result", (data) => {
    if (data && data.adshield_result) {
      showResult(data.adshield_result);
    } else {
      resultDiv.textContent = "⚠️ Open a website tab (not chrome://) to scan.";
      resultDiv.className = "warning";
    }
  });

  function showResult(result) {
    if (!result) {
      resultDiv.textContent = "⚠️ No scan result available.";
      resultDiv.className = "warning";
      return;
    }
    if (result.error) {
      resultDiv.textContent = "⚠️ Error: " + result.error;
      resultDiv.className = "dangerous";
      return;
    }
    const score = Number(result.score || 0);
    if (score >= 70) {
      resultDiv.textContent = `🟢 Site is Safe (${score})`;
      resultDiv.className = "safe";
    } else if (score >= 40) {
      resultDiv.textContent = `🟡 Suspicious (${score})`;
      resultDiv.className = "suspicious";
    } else {
      resultDiv.textContent = `🔴 Dangerous (${score})`;
      resultDiv.className = "dangerous";
    }
  }
});
