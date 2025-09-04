# 🛡️ VisionGuard

VisionGuard is a **Chrome Extension + Flask Backend** project that checks if websites and their ads are safe or dangerous.

---

## 🚀 How It Works
1. **Chrome Extension** collects the current website URL.
2. Sends the URL to the **Flask server**.
3. Flask runs multiple **security checks**:
   - Phishing check
   - Malware blacklist check
   - Unwanted software detection
   - VirusTotal API check
   - Google Vision API (OCR) → Reads text in images/banners (like "Win iPhone", "Free Money").
4. Flask calculates a **safety score (0–100)**.
5. The extension shows a result:
   - 🟢 Safe  
   - 🟡 Suspicious  
   - 🔴 Dangerous  

---

## 🖼️ Example
Visiting a site: `http://suspicious-giveaway.com`  
- OCR detects: *“Win iPhone”*, *“Free”*  
- VirusTotal marks it suspicious  
- Score = 25 (Dangerous)  
- Popup shows: 🔴 **Dangerous**

---

## 📦 Components
- **Chrome Extension** → User interface in browser  
- **Flask (Python)** → Backend server that runs checks  
- **Google Vision API** → OCR for images/ads  
- **VirusTotal API** → Reputation check  

---

## 🎯 Why Use VisionGuard?
- Protects against **phishing** and **scam ads**  
- Warns before downloading **malware**  
- Runs in **real-time** as you browse  
