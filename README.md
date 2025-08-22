Typosquatting Detection

A Flask-based web application that detects typosquatting (malicious domains mimicking trusted brands). The system compares user-input URLs against a trusted brand list and identifies suspicious variations.

🚀 Features

Detects typosquatting domains in real-time.

Maintains a list of trusted brands (trusted_brands.py).

Implements domain similarity checks (typosquat_checker.py).

Flask web interface (app.py) with HTML templates and CSS/JS styling.

User-friendly frontend (templates/, static/).

🗂 Project Structure
typosquattingDetection/
│── app.py                # Flask app (main entry point)
│── trusted_brands.py     # Trusted brands list
│── typosquat_checker.py  # Typosquatting detection logic
│── static/               # CSS, JS, images
│── templates/            # HTML templates
│── __pycache__/          # Cached Python files

⚙️ Installation & Setup
1️⃣ Clone the Repository
git clone https://github.com/govardhanhl/typosquattingDetection.git
cd typosquattingDetection

2️⃣ Create Virtual Environment (Optional but recommended)
python -m venv venv
source venv/bin/activate   # On Linux/Mac
venv\Scripts\activate      # On Windows

3️⃣ Install Dependencies
pip install -r requirements.txt


(Create a requirements.txt if not already done. Suggested content below ⬇️)

flask
tldextract
python-Levenshtein

4️⃣ Run the Application
python app.py

5️⃣ Access in Browser
http://127.0.0.1:5000/
