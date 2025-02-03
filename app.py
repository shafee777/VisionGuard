import os
import requests
import base64
from flask import Flask, render_template, request
import cv2
import numpy as np
import pytesseract
from PIL import Image
from io import BytesIO

app = Flask(__name__)

class AdShieldModel:
    def __init__(self):
        self.api_key_virustotal = os.getenv("VT_API_KEY", "5eae5564b4d8e96f22e6425b03b5a0762f914d44ab488d1e4552dbb4bc4f1015")
        self.api_key_safebrowsing = os.getenv("GSB_API_KEY", "AIzaSyDuFovmg7VPg59MJQPmTD_iQZOboSw_HAM")

    def analyze(self, url: str) -> dict:
        return {
            "vt_result": self.check_url_with_virustotal(url),
            "phishing_result": self.check_phishing_with_safebrowsing(url),
            "malware_result": self.check_malware_with_safebrowsing(url),
            "unwanted_software_result": self.check_unwanted_software_with_safebrowsing(url),
            "image_analysis": self.analyze_image(url)
        }

    def check_url_with_virustotal(self, url: str) -> dict:
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        headers = {"x-apikey": self.api_key_virustotal}
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            analysis_stats = json_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": analysis_stats.get("malicious", 0),
                "suspicious": analysis_stats.get("suspicious", 0),
                "harmless": analysis_stats.get("harmless", 0),
                "undetected": analysis_stats.get("undetected", 0)
            }
        return {"error": "Unable to check URL with VirusTotal"}

    def check_with_safebrowsing(self, url: str, threat_type: str) -> dict:
        request_body = {
            "client": {"clientId": "quata_adshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [threat_type],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        safebrowsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key_safebrowsing}"
        response = requests.post(safebrowsing_url, json=request_body)
        if response.status_code == 200:
            return {"matches": 'matches' in response.json()}
        return {"error": f"Error checking {threat_type.replace('_', ' ').title()} status"}

    def check_phishing_with_safebrowsing(self, url: str) -> dict:
        return self.check_with_safebrowsing(url, "PHISHING")

    def check_malware_with_safebrowsing(self, url: str) -> dict:
        return self.check_with_safebrowsing(url, "MALWARE")

    def check_unwanted_software_with_safebrowsing(self, url: str) -> dict:
        return self.check_with_safebrowsing(url, "UNWANTED_SOFTWARE")

    def analyze_image(self, url: str) -> dict:
        try:
            response = requests.get(url)
            image = Image.open(BytesIO(response.content))
            gray_image = cv2.cvtColor(np.array(image), cv2.COLOR_BGR2GRAY)
            _, binary = cv2.threshold(gray_image, 150, 255, cv2.THRESH_BINARY_INV)
            text = pytesseract.image_to_string(Image.fromarray(binary))

            suspicious_keywords = [
                "free", "urgent", "limited time offer", "click here", "win", "prize", "congratulations",
                "claim now", "winner", "lottery", "jackpot", "instant cash", "guaranteed", "exclusive deal",
                "only today", "special promotion", "act now", "don't miss", "risk-free", "easy money",
                "no investment", "make money fast", "double your income", "work from home", "miracle",
                "amazing", "unbelievable", "secret", "hidden", "unknown", "shocking", "one-time offer",
                "fast approval", "pre-approved", "zero cost", "extra income", "no risk", "100% free",
                "instant approval", "low-cost", "discount", "billionaire secret", "as seen on", "VIP",
                "confidential", "guaranteed results", "no credit check", "act fast", "order now", "no catch",
                "click below", "sign up free", "free gift", "urgent update", "verify account", "account suspended",
                "security alert", "bank notice", "unauthorized transaction", "suspicious activity", "reset password",
                "dear user", "official notice", "last warning", "identity verification", "update required",
                "confirm your details", "fake invoice", "you have been selected", "limited availability",
                "hot deal", "lowest price", "hurry up", "100% satisfaction", "guaranteed income", "cash reward",
                "bonus", "earn today", "win big", "get rich", "investment opportunity", "lotto", "you won",
                "financial freedom", "become a millionaire", "quick money", "easy loan", "no collateral",
                "government grant", "secret investment", "binary options", "crypto giveaway", "urgent payment",
                "unexpected gift", "claim your funds", "exclusive invitation", "confidential message",
                "this won't last", "high returns", "send money now", "wire transfer", "cheap offer"
            ]
            is_suspicious = any(keyword in text.lower() for keyword in suspicious_keywords)

            return {"text": text, "is_suspicious": is_suspicious}
        except Exception as e:
            return {"error": str(e)}

model = AdShieldModel()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['POST'])
def detect():
    ad_url = request.form.get('ad_url', '')
    results = model.analyze(ad_url)

    score = 100.0

    vt_result = results["vt_result"]
    if "error" not in vt_result:
        total_engines = sum(vt_result.values())
        if total_engines > 0:
            malicious_ratio = vt_result.get("malicious", 0) / total_engines
            suspicious_ratio = vt_result.get("suspicious", 0) / total_engines
            score -= malicious_ratio * 40 + suspicious_ratio * 20

    if results["phishing_result"].get("matches", False):
        score -= 20
    if results["malware_result"].get("matches", False):
        score -= 20
    if results["unwanted_software_result"].get("matches", False):
        score -= 10

    if results["image_analysis"].get("is_suspicious", False):
        score -= 10

    score = max(score, 0)
    score = round(score, 2)

    results["score"] = score

    return render_template('result.html', **results)

if __name__ == '__main__':
    app.run(debug=True)
