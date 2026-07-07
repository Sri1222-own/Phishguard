from flask import Flask, render_template, request
import re
import urllib.request
from urllib.parse import urlparse
from difflib import SequenceMatcher

app = Flask(__name__)


BRANDS = [
    "amazon", "google", "paypal", "facebook", "instagram",
    "apple", "microsoft", "netflix", "github", "linkedin",
    "youtube", "whatsapp", "twitter", "x", "snapchat",
    "telegram", "reddit", "discord", "tiktok", "pinterest",
    "yahoo", "bing", "outlook", "office", "adobe",
    "dropbox", "icloud", "spotify", "zoom", "shopify",
    "ebay", "walmart", "aliexpress", "flipkart", "myntra",
    "zomato", "swiggy", "uber", "ola", "airbnb",
    "booking", "paytm", "phonepe", "gpay", "razorpay",
    "stripe", "visa", "mastercard", "sbi", "hdfc",
    "icici", "axisbank", "kotak", "canarabank", "irctc",
    "uidai", "digilocker", "incometax", "coursera", "udemy"
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
    "won", "winner", "prize", "reward", "gift", "bonus",
    "cash", "lottery", "jackpot", "selected", "free"
]


URGENCY_WORDS = [
    "urgent", "now", "immediately", "limited time",
    "expires", "today", "final warning", "act fast"
]


ACTION_WORDS = [
    "click", "claim", "verify", "confirm", "update",
    "login", "sign in", "submit", "open", "receive"
]


RISKY_ATTACHMENTS = (
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".zip", ".rar"
)


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
        character_substitution = normalized_domain_name == brand and domain_name != brand
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


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    detector = "url"
    decoded_qr = ""

    if request.method == "POST":
        detector = request.form.get("detector", "url")

        if detector == "url":
            url = request.form.get("url", "")
            result = analyze_url(url)

        elif detector == "email":
            sender = request.form.get("sender", "")
            email_text = request.form.get("email_text", "")
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

    return render_template(
        "index.html",
        result=result,
        detector=detector,
        decoded_qr=decoded_qr,
    )


if __name__ == "__main__":
    app.run(debug=True)