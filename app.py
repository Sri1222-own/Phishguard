import urllib.request
import os
from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
import sqlite3
from datetime import datetime

app = Flask(__name__)

app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

scan_count = 0
threat_count = 0


def init_db():

    conn = sqlite3.connect("history.db")

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            detector TEXT,
            target TEXT,
            prediction TEXT,
            score INTEGER
        )
    """)

    try:
        cursor.execute("""
            ALTER TABLE scans
            ADD COLUMN reason TEXT
        """)
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


init_db()


def save_scan(detector, result, target=""):

    conn = sqlite3.connect("history.db")

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scans
        (time, detector, target, prediction, score, reason)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now().strftime("%H:%M:%S"),
            detector.upper(),
            target,
            result["prediction"],
            result["score"],
            ", ".join(result.get("reasons", [])),
        ),
    )

    conn.commit()
    conn.close()


def get_history():

    conn = sqlite3.connect("history.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT detector, target, prediction, score, time, reason
        FROM scans
        ORDER BY id DESC
        LIMIT 5
""")

    history = cursor.fetchall()

    conn.close()

    return history


def get_recent_activity():

    conn = sqlite3.connect("history.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT time, detector, prediction, score
        FROM scans
        ORDER BY id DESC
        LIMIT 5
    """)

    activity = cursor.fetchall()

    conn.close()

    return activity


def get_stats():

    conn = sqlite3.connect("history.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE prediction = 'HIGH RISK PHISHING'
    """)

    threats = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
    """)

    total_scans = cursor.fetchone()[0]

    conn.close()

    return total_scans, threats


BRANDS = [
    "amazon",
    "google",
    "paypal",
    "facebook",
    "instagram",
    "apple",
    "microsoft",
    "netflix",
    "github",
    "linkedin",
    "youtube",
    "whatsapp",
    "twitter",
    "x",
    "snapchat",
    "telegram",
    "reddit",
    "discord",
    "tiktok",
    "pinterest",
    "yahoo",
    "bing",
    "outlook",
    "office",
    "adobe",
    "dropbox",
    "icloud",
    "spotify",
    "zoom",
    "shopify",
    "ebay",
    "walmart",
    "aliexpress",
    "flipkart",
    "myntra",
    "zomato",
    "swiggy",
    "uber",
    "ola",
    "airbnb",
    "booking",
    "paytm",
    "phonepe",
    "gpay",
    "razorpay",
    "stripe",
    "visa",
    "mastercard",
    "sbi",
    "hdfc",
    "icici",
    "axisbank",
    "kotak",
    "canarabank",
    "irctc",
    "uidai",
    "digilocker",
    "incometax",
    "coursera",
    "udemy",
]


SUSPICIOUS_KEYWORDS = {
    "login": 15,
    "verify": 15,
    "update": 15,
    "secure": 15,
    "account": 10,
    "password": 15,
    "bank": 20,
    "paypal": 20,
    "signin": 15,
    "confirm": 15,
    "claim": 20,
    "prize": 25,
    "reward": 20,
    "winner": 25,
    "free": 10,
    "phishing": 30,
    "malware": 30,
    "hack": 25,
    "fake": 25,
    "fraud": 30,
    "scam": 30,
    "steal": 30,
}


EMAIL_WARNING_WORDS = {
    "urgent": 15,
    "verify your account": 25,
    "account suspended": 25,
    "password expired": 20,
    "click here": 15,
    "limited time": 10,
    "security alert": 15,
    "unusual activity": 20,
    "confirm your identity": 25,
    "you have won": 25,
    "you won": 25,
    "congratulations": 20,
    "claim your reward": 30,
    "claim your prize": 30,
    "reward": 20,
    "prize": 25,
    "winner": 25,
    "$": 10,
}


REWARD_WORDS = [
    "won",
    "winner",
    "prize",
    "reward",
    "gift",
    "bonus",
    "cash",
    "lottery",
    "jackpot",
    "selected",
    "free",
]


URGENCY_WORDS = [
    "urgent",
    "now",
    "immediately",
    "limited time",
    "expires",
    "today",
    "final warning",
    "act fast",
]


ACTION_WORDS = [
    "click",
    "claim",
    "verify",
    "confirm",
    "update",
    "login",
    "sign in",
    "submit",
    "open",
    "receive",
]


RISKY_ATTACHMENTS = (".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".zip", ".rar")


SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "qrco.de",
]
# Local phishing URL database

PHISHING_DATABASE_FILE = "phishing_urls.txt"


def load_phishing_database():
    phishing_urls = set()

    try:
        with open(PHISHING_DATABASE_FILE, "r") as file:
            for line in file:
                url = line.strip().lower()

                if url:
                    phishing_urls.add(url)

    except FileNotFoundError:
        print("phishing_urls.txt not found")

    return phishing_urls


PHISHING_URLS = load_phishing_database()


def check_phishing_database(url):
    clean_url = url.strip().lower()

    if clean_url in PHISHING_URLS:
        return True

    return False


def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()


def get_domain(url):
    clean_url = url.strip().lower()

    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    parsed = urlparse(clean_url)
    return parsed.netloc.replace("www.", "")


def get_domain_name(domain):
    labels = domain.split(".")

    if len(labels) >= 2:
        return labels[-2]

    return domain


def add_score(score, points):
    return min(score + points, 100)


def risk_label(score):
    if score >= 80:
        return "HIGH RISK PHISHING"

    if score >= 50:
        return "SUSPICIOUS"

    if score >= 20:
        return "MEDIUM RISK"

    return "SAFE"


def expand_redirect(url):
    clean_url = url.strip()

    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    try:
        request_obj = urllib.request.Request(
            clean_url,
            method="HEAD",
            headers={"User-Agent": "PhishGuard/1.0"},
        )

        with urllib.request.urlopen(request_obj, timeout=5) as response:
            return response.geturl()

    except Exception:
        return clean_url


def analyze_url(url, check_redirect=True):
    score = 0
    reasons = []

    if check_phishing_database(url):
        score = add_score(score, 80)
        reasons.append("URL found in local phishing database")

    url = url.strip().lower()
    domain = get_domain(url)
    domain_name = get_domain_name(domain)

    if domain in SHORTENER_DOMAINS:
        score = add_score(score, 25)
        reasons.append("Uses a URL shortener or QR redirect service")

        if check_redirect:
            final_url = expand_redirect(url)

            if final_url.lower().strip("/") != url.lower().strip("/"):
                reasons.append(f"Redirects to: {final_url}")
                final_result = analyze_url(final_url, check_redirect=False)
                score = add_score(score, min(final_result["score"], 60))

                for reason in final_result["reasons"]:
                    if reason != "No common phishing signs found":
                        reasons.append(f"Final link: {reason}")

    if url.startswith("http://"):
        score = add_score(score, 20)
        reasons.append("Uses HTTP instead of HTTPS")

    if "@" in url:
        score = add_score(score, 30)
        reasons.append("Contains @ symbol")

    if len(url) > 75:
        score = add_score(score, 10)
        reasons.append("URL is unusually long")

    if domain.count(".") > 3:
        score = add_score(score, 10)
        reasons.append("Domain has too many dots")

    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.search(ip_pattern, domain):
        score = add_score(score, 25)
        reasons.append("Uses an IP address instead of a domain name")

    for word, points in SUSPICIOUS_KEYWORDS.items():
        if word in url:
            score = add_score(score, points)
            reasons.append(f"Contains suspicious keyword: {word}")

    normalized_domain_name = (
        domain_name.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
    )

    for brand in BRANDS:
        exact_brand_domain = domain_name == brand
        character_substitution = (
            normalized_domain_name == brand and domain_name != brand
        )
        lookalike_typo = similar(domain_name, brand) > 0.8 and domain_name != brand

        if not exact_brand_domain and (character_substitution or lookalike_typo):
            score = add_score(score, 30)
            reasons.append(
                f"Possible brand impersonation / typosquatting of {brand.title()}"
            )
            break

    if not reasons:
        reasons.append("No common phishing signs found")

    return {
        "score": score,
        "prediction": risk_label(score),
        "reasons": reasons,
        "input": url,
    }


def find_urls(text):
    pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s]*)"
    return re.findall(pattern, text)


def analyze_email(sender, email_text):
    score = 0
    reasons = []

    sender = sender.strip().lower()
    email_text = email_text.strip().lower()

    if sender:
        sender_domain = sender.split("@")[-1] if "@" in sender else sender
        sender_domain_name = get_domain_name(sender_domain)

        if "@" not in sender:
            score = add_score(score, 15)
            reasons.append("Sender address does not look like a valid email")

        for brand in BRANDS:
            if similar(sender_domain_name, brand) > 0.8 and sender_domain_name != brand:
                score = add_score(score, 30)
                reasons.append(f"Sender may be impersonating {brand.title()}")
                break

    for phrase, points in EMAIL_WARNING_WORDS.items():
        if phrase in email_text:
            score = add_score(score, points)
            reasons.append(f"Email contains suspicious phrase: {phrase}")

    reward_count = sum(1 for word in REWARD_WORDS if word in email_text)
    urgency_count = sum(1 for word in URGENCY_WORDS if word in email_text)
    action_count = sum(1 for word in ACTION_WORDS if word in email_text)

    if reward_count >= 1:
        score = add_score(score, 20)
        reasons.append("Email contains prize/reward related wording")

    if urgency_count >= 1:
        score = add_score(score, 20)
        reasons.append("Email creates urgency or pressure")

    if action_count >= 1:
        score = add_score(score, 20)
        reasons.append("Email asks the user to take action")

    if reward_count >= 1 and action_count >= 1:
        score = add_score(score, 30)
        reasons.append("Prize/reward message asks user to click or claim")

    if urgency_count >= 1 and action_count >= 1:
        score = add_score(score, 25)
        reasons.append("Urgent message asks user to take action")

    for attachment in RISKY_ATTACHMENTS:
        if attachment in email_text:
            score = add_score(score, 25)
            reasons.append(f"Mentions risky attachment type: {attachment}")

    urls = find_urls(email_text)

    if urls:
        reasons.append(f"Found {len(urls)} link(s) in the email")

        for found_url in urls[:3]:
            url_result = analyze_url(found_url)

            if url_result["score"] >= 20:
                score = add_score(score, min(url_result["score"], 40))
                reasons.append(f"Suspicious link found: {found_url}")
    else:
        reasons.append("No links found in the email text")

    if not reasons:
        reasons.append("No common phishing signs found")

    return {
        "score": score,
        "prediction": risk_label(score),
        "reasons": reasons,
        "input": sender,
    }


def decode_qr_code(file_storage):
    try:
        import cv2
        import numpy as np
    except ImportError:
        return None, "QR scanning needs opencv-python and numpy installed"

    file_bytes = np.frombuffer(file_storage.read(), np.uint8)
    image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

    if image is None:
        return None, "Uploaded file is not a readable image"

    detector = cv2.QRCodeDetector()
    decoded_text, points, _ = detector.detectAndDecode(image)

    if not decoded_text:
        return None, "No QR code was detected in the uploaded image"

    return decoded_text, None


@app.route("/history")
def history_page():

    conn = sqlite3.connect("history.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT time, detector, prediction, score, reason
        FROM scans
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    conn.close()

    return render_template("history.html", scans=scans)


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    detector = "url"
    decoded_qr = ""

    if request.method == "POST":
        detector = request.form.get("detector", "url")

        if detector == "url":

            url = request.form.get("url", "").strip()

            result = analyze_url(url)

        elif detector == "email":

            sender = request.form.get("sender", "").strip()
            email_text = request.form.get("email_text", "").strip()

            if "@" not in sender or "." not in sender:
                result = {
                    "prediction": "INVALID EMAIL",
                    "score": 0,
                    "reasons": [
                        "Please enter a valid sender email address",
                        "Example: sender@example.com"
                    ]
                }

            elif len(email_text) < 5:
                result = {
                    "prediction": "EMAIL CONTENT TOO SHORT",
                    "score": 0,
                    "reasons": [
                        "Please enter the email message content"
                    ]
                }

            else:
                result = analyze_email(sender, email_text)

        elif detector == "qr":
            qr_file = request.files.get("qr_file")

            if qr_file and qr_file.filename:
                decoded_qr, error = decode_qr_code(qr_file)

                if error:
                    result = {
                        "score": 0,
                        "prediction": "QR SCAN ERROR",
                        "reasons": [error],
                        "input": "",
                    }
                else:
                    result = analyze_url(decoded_qr)
            else:
                result = {
                    "score": 0,
                    "prediction": "QR SCAN ERROR",
                    "reasons": ["Please upload a QR code image"],
                    "input": "",
                }

        if result:

            if detector == "qr":
                target = decoded_qr if decoded_qr else "QR IMAGE"
                save_scan(detector, result, target)

            elif detector == "email":
                target = sender
                save_scan(detector, result, target)

            elif detector == "url":
                save_scan(detector, result, url)  
    history = get_history()

    activity = get_recent_activity()

    scan_count, threat_count = get_stats()

    print("TOTAL:", scan_count, "THREATS:", threat_count)

    return render_template(
        "index.html",
        result=result,
        detector=detector,
        decoded_qr=decoded_qr,
        scan_count=scan_count,
        threat_count=threat_count,
        history=history,
        activity=activity,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
