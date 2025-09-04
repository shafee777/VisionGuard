# App.py

import os
import requests
import base64
from flask import Flask, render_template, request, redirect, url_for,jsonify
import cv2
from urllib.parse import urljoin, unquote
from bs4 import BeautifulSoup
import numpy as np
import pytesseract
from PIL import Image
from io import BytesIO
from flask_cors import CORS
import re

SUSPICIOUS_KEYWORDS = [
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

app = Flask(__name__)
CORS(app)
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










    def ocr_google_vision(image_url=None, image_bytes=None, api_key=None):
 
        if not api_key:
            raise RuntimeError("Missing Google Vision API key")

        endpoint = f"https://vision.googleapis.com/v1/images:annotate?key={api_key}"
        # Build request body depending on whether we have a URL or bytes
        if image_bytes is not None:
            content_b64 = base64.b64encode(image_bytes).decode("utf-8")
            img_obj = {"image": {"content": content_b64}}
        else:
            img_obj = {"image": {"source": {"imageUri": image_url}}}

        body = {
            "requests": [
                {
                    **img_obj,
                    "features": [{"type": "DOCUMENT_TEXT_DETECTION", "maxResults": 1}],
                    "imageContext": {}
                }
            ]
        }

        resp = requests.post(endpoint, json=body, timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"Vision API HTTP {resp.status_code}: {resp.text}")

        j = resp.json()
        # Prefer fullTextAnnotation if present
        try:
            rr = j.get("responses", [])[0]
            if "fullTextAnnotation" in rr and rr["fullTextAnnotation"].get("text"):
                return rr["fullTextAnnotation"]["text"]
            # Fallback to textAnnotations
            ta = rr.get("textAnnotations")
            if ta and len(ta) > 0:
                return ta[0].get("description", "")
            return ""
        except Exception as e:
            raise RuntimeError("Vision API response parse error: " + str(e))


    def analyze_image(self, url: str) -> dict:
        """
        Enhanced image analysis using Google Cloud Vision.
        Returns dict: {"text", "is_suspicious", "found_keywords", "image_url"} or {"error": "..."}
        """
        api_key = os.getenv("GOOGLE_VISION_API_KEY")
        try:
            # Helper to fetch image bytes (handles data: URIs and http(s) fetch)
            def get_image_bytes(src, page_url=None):
                src = src.strip()
                if src.startswith("data:"):
                    # data URI, possibly percent-encoded
                    try:
                        header, data = src.split(",", 1)
                    except ValueError:
                        return None, "malformed data URI"
                    try:
                        data = unquote(data)
                        if ";base64" in header:
                            raw = base64.b64decode(data)
                        else:
                            raw = data.encode("utf-8")
                        return raw, None
                    except Exception as e:
                        return None, f"data URI decode error: {e}"
                # Normal URL: resolve relative if needed
                full = urljoin(page_url or "", src)
                try:
                    r = requests.get(full, timeout=10, headers={"User-Agent": "AdShield/1.0"})
                except Exception as e:
                    return None, f"image fetch failed: {e}"
                if r.status_code != 200:
                    return None, f"image fetch HTTP {r.status_code}"
                ctype = r.headers.get("Content-Type", "")
                if "svg" in ctype or full.lower().endswith(".svg"):
                    return None, "SVG (not supported)"
                return r.content, None

            # If the provided URL looks like an image or data URI, prefer that first
            if re.search(r'\.(jpe?g|png|gif|bmp|webp)(?:\?.*)?$', url, re.I) or url.strip().lower().startswith("data:"):
                candidate_img = url
            else:
                # Fetch HTML and find candidate images
                try:
                    page_resp = requests.get(url, timeout=10, headers={"User-Agent": "AdShield/1.0"})
                except Exception as e:
                    return {"error": f"Page fetch failed: {e}"}
                if page_resp.status_code != 200:
                    return {"error": f"Page fetch failed ({page_resp.status_code})"}

                soup = BeautifulSoup(page_resp.text, "html.parser")
                imgs = []
                for img in soup.find_all("img"):
                    src = img.get("src") or img.get("data-src") or img.get("data-original")
                    if not src:
                        continue
                    try:
                        w = int(img.get("width")) if img.get("width") else 0
                        h = int(img.get("height")) if img.get("height") else 0
                    except:
                        w, h = 0, 0
                    meta = (img.get("alt") or "") + " " + " ".join(img.get("class", []) or []) + " " + (img.get("id") or "")
                    imgs.append((src, w, h, meta))

                if not imgs:
                    return {"error": "No images found on page"}

                def score_candidate(c):
                    src, w, h, meta = c
                    score = (w * h) if (w and h) else 0
                    if any(k in meta.lower() for k in ("ad", "ads", "advert", "banner", "sponsor")):
                        score += 1000000
                    return score

                imgs.sort(key=score_candidate, reverse=True)
                candidate_img = imgs[0][0]
                candidate_img = urljoin(url, candidate_img)

            # If candidate is data URI, decode and send bytes to Vision; otherwise try Vision with imageUri first
            if candidate_img.startswith("data:"):
                image_bytes, err = get_image_bytes(candidate_img, page_url=url)
                if err:
                    return {"error": err}
                try:
                    text = ocr_google_vision(image_bytes=image_bytes, api_key=api_key)
                except Exception as e:
                    return {"error": f"Vision API error: {e}", "image_url": candidate_img}
            else:
                # Try Vision with imageUri (avoids sending base64 bytes). If API can't access the image, fallback to downloading bytes.
                try:
                    text = ocr_google_vision(image_url=candidate_img, api_key=api_key)
                    # If empty, it's possible Vision couldn't access the image; try bytes fallback
                    if not text:
                        # download bytes and try again
                        image_bytes, err = get_image_bytes(candidate_img, page_url=url)
                        if err:
                            return {"error": err, "image_url": candidate_img}
                        text = ocr_google_vision(image_bytes=image_bytes, api_key=api_key)
                except Exception as e:
                    # try bytes fallback if imageUri call failed
                    image_bytes, err = get_image_bytes(candidate_img, page_url=url)
                    if err:
                        return {"error": f"Vision API error and image fetch failed: {e}; {err}", "image_url": candidate_img}
                    try:
                        text = ocr_google_vision(image_bytes=image_bytes, api_key=api_key)
                    except Exception as e2:
                        return {"error": f"Vision API error: {e2}", "image_url": candidate_img}

            # Check suspicious keywords (make sure SUSPICIOUS_KEYWORDS present at module level)
            text_lower = (text or "").lower()
            found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
            is_suspicious = len(found) > 0

            return {"text": text, "is_suspicious": is_suspicious, "found_keywords": found, "image_url": candidate_img}
        except Exception as exc:
            return {"error": str(exc)}











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
        text = results["image_analysis"].get("text", "")
        suspicious_keywords = [
            "free", "urgent", "limited time offer", "click here", "win", "prize", "congratulations",
            "claim now", "winner", "lottery", "jackpot", "instant cash", "guaranteed", "exclusive deal",
            "only today", "special promotion", "act now", "don't miss", "risk-free", "easy money",
            "no investment", "make money fast", "double your income", "work from home", "miracle",
            "amazing", "unbelievable", "secret", "hidden", "unknown", "shocking", "one-time offer",
            "fast approval", "pre-approved", "zero cost", "extra income", "no risk", "100{%} free",
            "instant approval", "low-cost", "discount", "billionaire secret", "as seen on", "VIP",
            "confidential", "guaranteed results", "no credit check", "act fast", "order now", "no catch",
            "click below", "sign up free", "free gift", "urgent update", "verify account", "account suspended",
            "security alert", "bank notice", "unauthorized transaction", "suspicious activity", "reset password",
            "dear user", "official notice", "last warning", "identity verification", "update required",
            "confirm your details", "fake invoice", "you have been selected", "limited availability",
            "hot deal", "lowest price", "hurry up", "100{%} satisfaction", "guaranteed income", "cash reward",
            "bonus", "earn today", "win big", "get rich", "investment opportunity", "lotto", "you won",
            "financial freedom", "become a millionaire", "quick money", "easy loan", "no collateral",
            "government grant", "secret investment", "binary options", "crypto giveaway", "urgent payment",
            "unexpected gift", "claim your funds", "exclusive invitation", "confidential message",
            "this won't last", "high returns", "send money now", "wire transfer", "cheap offer"
        ]
        extracted_words = [word for word in suspicious_keywords if word in text.lower()]

        if extracted_words:
            return render_template('confirm.html', extracted_words=extracted_words)

    score = max(score, 0)
    score = round(score, 2)

    results["score"] = score

    return render_template('result.html', **results)

@app.route('/confirm')
def confirm():
    response = request.args.get('response', 'no')
    if response == 'yes':
        return "This ad is likely targeted based on your recent activity."
    else:
        return "This ad is not confirmed to be targeted."

@app.route('/api/detect', methods=['POST'])
def api_detect():
    data = request.get_json()
    print("📥 Received JSON:", data) 
    if not data or "ad_url" not in data:
        return jsonify({"error": "Missing ad_url"}), 400

    ad_url = data["ad_url"]
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
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
