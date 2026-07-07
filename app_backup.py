from flask import Flask, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():

    result = ""
    score = 0
    reasons = []

    if request.method == "POST":

        url = request.form["url"].strip().lower()

        # Rule 1: HTTP
        if url.startswith("http://"):
            score += 20
            reasons.append("❌ Uses HTTP instead of HTTPS")

        # Rule 2: @ symbol
        if "@" in url:
            score += 30
            reasons.append("❌ Contains @ symbol")

        # Rule 3: Long URL
        if len(url) > 75:
            score += 10
            reasons.append("❌ URL is unusually long")

        # Rule 4: Too many dots
        if url.count(".") > 3:
            score += 10
            reasons.append("❌ Too many dots in URL")

        # Rule 5: IP Address
        ip_pattern = r'^(http://|https://)?(\d{1,3}\.){3}\d{1,3}'
        if re.search(ip_pattern, url):
            score += 25
            reasons.append("❌ Uses an IP address")

        # Rule 6: Suspicious keywords
        keywords = {
            "login":15,
            "verify":15,
            "update":15,
            "secure":15,
            "account":10,
            "password":15,
            "bank":20,
            "paypal":20,
            "signin":15,
            "confirm":15
        }

        for word, points in keywords.items():
            if word in url:
                score += points
                reasons.append(f"❌ Contains '{word}'")

        # Rule 7: Too many special characters
        special = sum(url.count(x) for x in ["-","_","=","%","?","&"])

        if special > 5:
            score += 10
            reasons.append("❌ Too many special characters")

        # Final Prediction
        if score >= 80:
            result = "🚨 HIGH RISK PHISHING WEBSITE"

        elif score >= 50:
            result = "⚠️ SUSPICIOUS WEBSITE"

        elif score >= 20:
            result = "🟡 MEDIUM RISK"

        else:
            result = "✅ SAFE"

    return f"""
<!DOCTYPE html>
<html>

<head>

<title>PhishGuard</title>

<style>

body{{
font-family:Arial;
background:#eef2f7;
text-align:center;
padding:40px;
}}

.container{{
background:white;
padding:30px;
border-radius:12px;
width:70%;
margin:auto;
box-shadow:0px 0px 15px lightgray;
}}

input{{
width:90%;
padding:12px;
font-size:16px;
}}

button{{
padding:12px 25px;
margin-top:15px;
font-size:16px;
background:#1565C0;
color:white;
border:none;
cursor:pointer;
}}

.score{{
font-size:28px;
color:#d32f2f;
font-weight:bold;
}}

.result{{
font-size:24px;
margin-top:20px;
}}

ul{{
text-align:left;
width:70%;
margin:auto;
}}

</style>

</head>

<body>

<div class="container">

<h1>🛡️ PhishGuard</h1>

<h2>Advanced URL Phishing Detector</h2>

<form method="POST">

<input
type="text"
name="url"
placeholder="Paste URL here">

<br>

<button>

Analyze URL

</button>

</form>

<br>

<div class="score">

Risk Score: {score}%

</div>

<div class="result">

{result}

</div>

<h3>Reasons</h3>

<ul>

{''.join(f'<li>{r}</li>' for r in reasons)}

</ul>

</div>

</body>

</html>
"""

if __name__ == "__main__":
    app.run(debug=True)