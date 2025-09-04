VisionGuard
      VisionGuard is a project that checks if a website (or its ads) are safe or dangerous.
      It works as a Chrome Extension that connects to a Flask backend (Python server) running on your computer.

🔹 How it Works 
1. You Install the Chrome Extension

The extension shows a small icon in Chrome.

When you click the icon (or switch to a new website tab), it starts a scan.

2. Extension Collects Website Info

The extension looks at the URL of the current site you are visiting.

It sends this URL to the Flask server (running on http://127.0.0.1:5000).

3. Flask Backend Analyzes the Site

The Python server runs different security checks:

Phishing Check → See if the URL looks suspicious or matches phishing databases.

Malware Check → See if the site is blacklisted.

Unwanted Software Check → Detect hidden risky software.

VirusTotal API Check → Cross-check with an online malware scanning service.

Image Analysis (OCR) → Look at images/banners on the page.

Uses Google Vision API to “read” text inside images.

Searches for keywords like “Free Money”, “Click Here”, “Win iPhone”, which are common in scams/ads.

The backend then calculates a safety score (0–100).

4. Extension Shows Results to User

The extension popup window shows one of three statuses:

🟢 Safe (score high, no issues)

🟡 Suspicious (medium risk)

🔴 Dangerous (low score, risky signs found)

This way, users immediately know if the site is trustworthy.

🔹 Example Workflow

You open a site: http://suspicious-giveaway.com

The extension automatically sends the URL → Flask server.

Flask:

Finds a banner image: “Congratulations! You won an iPhone!”

OCR detects the words “Win” + “Free”.

VirusTotal says the site is suspicious.

Flask sends back: Score = 25 (Dangerous)

Extension popup shows:
🔴 Dangerous (25)

🔹 Why It’s Useful

Protects users from phishing and scam ads.

Helps people avoid fake offers and malware downloads.

Works in real time as you browse.

🔹 Components in Simple Words

Chrome Extension = The “frontend” (what you see in browser).

Flask Server (Python) = The “backend brain” that does the scanning.

Google Vision API = Reads text from images (like banners/ads).

VirusTotal API = Cross-checks site reputation.
