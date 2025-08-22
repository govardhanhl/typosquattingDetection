from flask import Flask, render_template, request, redirect
import tldextract
import Levenshtein
from difflib import SequenceMatcher
import re

app = Flask(__name__)

# Trusted domains list
trusted_domains = [
    "google.com", "amazon.in", "microsoft.com", "icicibank.com",
    "karnataka.gov.in", "sbi.co.in", "portal.office.com", "irctc.co.in",
    "linkedin.com", "nytimes.com", "flipkart.com", "airindia.com"
]

def get_main_domain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

def is_valid_url(url):
    pattern = r"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, url)

def detect_typosquatting(input_url):
    if not is_valid_url(input_url):
        return {
            "status": "Phishing",
            "reason": "URL is improperly formatted or incomplete.",
            "input_url": input_url
        }

    extracted = tldextract.extract(input_url)
    if not extracted.domain.strip() or not extracted.suffix.strip():
        return {
            "status": "Phishing",
            "reason": "Malformed or incomplete URL.",
            "input_url": input_url
        }

    input_domain = get_main_domain(input_url)

    for trusted in trusted_domains:
        trusted_domain = get_main_domain(trusted)
        similarity = SequenceMatcher(None, input_domain, trusted_domain).ratio()
        distance = Levenshtein.distance(input_domain, trusted_domain)

        if similarity > 0.8 and similarity < 1.0 and distance <= 2:
            return {
                "status": "Phishing",
                "reason": f"URL is suspiciously similar to {trusted_domain} (Similarity: {similarity:.2f}, Distance: {distance})",
                "input_url": input_url
            }

    if input_domain in [get_main_domain(td) for td in trusted_domains]:
        return {
            "status": "Safe",
            "reason": "Exact match with trusted domain.",
            "input_url": input_url
        }

    return {
        "status": "Safe",
        "reason": "No suspicious patterns found.",
        "input_url": input_url
    }

# Flask Routes

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"]
    result = detect_typosquatting(url)

    # If Safe, show visit link button
    if result["status"] == "Safe":
        return render_template("result.html", result=result, show_link=True)
    else:
        return render_template("result.html", result=result, show_link=False)

if __name__ == "__main__":
    app.run(debug=True)
