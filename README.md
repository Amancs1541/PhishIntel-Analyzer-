# 🛡️ PhishIntel Analyzer

A Multi-Layered Hybrid Framework for Phishing Email Detection Using Zero-Shot NLP and Threat Intelligence

PhishIntel Analyzer is a web-based phishing email analysis platform that integrates zero-shot Natural Language Processing (NLP), email header inspection, URL intelligence enrichment, and OSINT-based Threat Intelligence to deliver transparent, explainable, and practical phishing detection.
The system is designed for academic research, cybersecurity education, and lightweight operational analysis.

# Key Features

- Zero-shot phishing intent detection using facebook/bart-large-mnli

- Email header inspection for spoofing and routing anomalies

- URL and IP reputation analysis

- Threat Intelligence integration (VirusTotal, AbuseIPDB, AlienVault OTX)

- Rule-based risk scoring for interpretability

- Web-based dashboard with structured analysis reports

- Flask-based lightweight architecture

# 🧱 Technology Stack

### Backend: Python, Flask

### NLP Engine: Hugging Face Transformers

### Database: SQLite (via Flask-SQLAlchemy)

### Authentication: Flask-Login

### Threat Intelligence: REST APIs

### Deployment: Local / Academic environments

# 🔹 Python Dependencies

The project uses the following libraries (as defined in requirements.txt):

```
flask==3.0.0
flask-login==0.6.3
flask-sqlalchemy==3.1.1
python-dotenv==1.0.1
werkzeug==3.0.1
requests==2.32.3
transformers==4.43.3

```
# 🛠️ Environment Setup
1️⃣ Clone the Repository

```
git clone https://github.com/your-username/phishintel-analyzer.git
cd phishintel-analyzer

```

# 2️⃣ Create a Virtual Environment

```
python3 -m venv venv
source venv/bin/activate
```
### (Windows: venv\Scripts\activate)

3️⃣ Install Dependencies
```
pip install -r requirements.txt
```
# ▶️ Running the Application
```
python app.py
```

# 🧩 System Architecture (Overview)
```
User → Email Upload → Preprocessing
      → NLP Analysis
      → Header Analysis
      → URL & Attachment Analysis
      → Threat Intelligence Lookup
      → Risk Scoring Engine
      → Final Report
```

# 📊 Evaluation Approach

## PhishIntel Analyzer evaluates emails using:


## Zero-shot NLP confidence scores


## Rule-based heuristic indicators


## Threat Intelligence reputation results


## Aggregated phishing risk scoring
