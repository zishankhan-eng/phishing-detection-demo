"""Phishing Attack Simulation and Detection - safe, local educational demo.
Uses only Python's standard library. Does not send emails or collect credentials.
Run: python app.py
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import json, re, html

HOST, PORT = "127.0.0.1", 8000

SUSPICIOUS_PHRASES = [
    "verify your account", "account suspended", "urgent action", "act now",
    "password expires", "confirm your password", "unusual activity",
    "you have won", "claim your prize", "payment failed", "click immediately",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"}


def extract_urls(text):
    return re.findall(r"https?://[^\s<>\"']+", text, flags=re.I)


def analyse_url(url):
    flags, score = [], 0
    candidate = url if re.match(r"^https?://", url, re.I) else "http://" + url
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return ["URL ka domain read nahi ho saka"], 25
        if parsed.scheme != "https":
            flags.append("HTTPS nahi hai"); score += 10
        if host in SHORTENERS:
            flags.append("URL shortener use hua hai"); score += 20
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            flags.append("Domain ki jagah IP address hai"); score += 25
        if "xn--" in host:
            flags.append("Punycode domain: spelling disguise ho sakti hai"); score += 20
        if "@" in parsed.netloc:
            flags.append("URL mein @ symbol hai"); score += 20
        if len(host) > 45 or host.count("-") >= 3:
            flags.append("Domain unusually long ya hyphen-heavy hai"); score += 10
        if len(parsed.path) > 70:
            flags.append("URL path unusually long hai"); score += 5
    except Exception:
        flags.append("URL format invalid hai"); score += 25
    return flags, min(score, 60)


def analyse_email(sender, subject, body):
    text = f"{sender} {subject} {body}".lower()
    findings, score = [], 0
    for phrase in SUSPICIOUS_PHRASES:
        if phrase in text:
            findings.append(f"Urgent/suspicious phrase: '{phrase}'")
            score += 12
    if re.search(r"\b(password|otp|pin|cvv)\b", text):
        findings.append("Sensitive information maangne ka indication")
        score += 20
    if re.search(r"\b(urgent|immediately|within 24 hours|last warning)\b", text):
        findings.append("Pressure ya urgency create ki ja rahi hai")
        score += 10
    urls = extract_urls(body)
    if not urls:
        findings.append("Email body mein koi direct URL nahi mila")
    for url in urls:
        url_flags, url_score = analyse_url(url)
        findings.extend([f"URL {url}: {flag}" for flag in url_flags])
        score += url_score
    if sender and not re.search(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", sender.strip()):
        findings.append("Sender email address ka format unusual hai")
        score += 10
    score = min(score, 100)
    level = "High Risk" if score >= 60 else "Medium Risk" if score >= 30 else "Low Risk"
    if not findings:
        findings.append("Koi configured warning indicator nahi mila")
    return {"score": score, "level": level, "findings": findings,
            "urls_found": urls,
            "advice": "Link par click na karein; sender ko official channel se verify karein. OTP/password kabhi share na karein."}


class Handler(BaseHTTPRequestHandler):
    def send_data(self, status, data, content_type="application/json; charset=utf-8"):
        raw = data.encode("utf-8") if isinstance(data, str) else json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open("index.html", "r", encoding="utf-8") as f:
                    self.send_data(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self.send_data(500, "index.html missing", "text/plain")
        else:
            self.send_data(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/scan":
            self.send_data(404, {"error": "Not found"}); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 20000:
                self.send_data(413, {"error": "Input too large"}); return
            payload = json.loads(self.rfile.read(length) or b"{}")
            result = analyse_email(str(payload.get("sender", ""))[:300],
                                   str(payload.get("subject", ""))[:500],
                                   str(payload.get("body", ""))[:10000])
            self.send_data(200, result)
        except (ValueError, json.JSONDecodeError):
            self.send_data(400, {"error": "Invalid request data"})

    def log_message(self, fmt, *args):
        print("[local-server] " + (fmt % args))


if __name__ == "__main__":
    print(f"Phishing Detection System running at http://{HOST}:{PORT}")
    print("Local educational demo only. Press Ctrl+C to stop.")
    HTTPServer((HOST, PORT), Handler).serve_forever()
