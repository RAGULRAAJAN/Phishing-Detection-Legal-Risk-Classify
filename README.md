# Phishing Detection & Legal Risk Classification System (Hybrid ML Pipeline)

An enterprise-grade security solution for analyzing phishing emails and mapping them to legal compliance frameworks. This system combines multiple machine learning architectures for high-accuracy threat detection with a rule-based engine to identify potential legal violations under global cybersecurity acts.

## 🌟 Core Idea
The project addresses the gap between **technical threat detection** and **legal accountability**. While most systems only identify if an email is phishing, this system explains *why* it is dangerous and *which laws* the attacker is violating (e.g., IT Act, DPDP Act, GDPR), providing SOC analysts with immediate actionable intelligence.

## 🚀 Key Upgrades & Features
We have significantly enhanced the system with the following upgrades:
- **Hybrid Ensemble Architecture**: Integrated a multi-model voting system combining Random Forest, BERT, and Isolation Forest.
- **Deep Semantic Analysis**: Leveraged transformer-based NLP (BERT) to detect spear-phishing that avoids traditional keyword filters.
- **Automated Legal Mapping**: A specialized engine that translates technical threat indicators into specific legal sections (e.g., Section 66C/66D of the IT Act).
- **Active Learning Loop**: Implementation of a feedback mechanism (`/api/v1/feedback`) to collect human-in-the-loop data for model retraining.
- **Sandboxed Link Preview**: A security feature to safely fetch and inspect link metadata without risking the user's environment.
- **SIEM-Ready Logging**: Structured JSON logs optimized for ingestion into Splunk, ELK, or other security monitoring platforms.

## 🛠️ Technology Stack
- **Frontend**: Vanilla HTML5, CSS3 (Glassmorphism design), JavaScript (ES6+).
- **Backend**: Python 3.9+, FastAPI (High-performance API framework).
- **ML Frameworks**: Scikit-learn, HuggingFace Transformers (PyTorch), Joblib.
- **Tools**: BeautifulSoup4 (Parsing), Aiohttp (Async Requests), Docker.

## 🧠 Machine Learning Models: Why & How?
The system uses a **Hybrid Ensemble Approach** to minimize false negatives:
1. **Random Forest (RF)**: 
   - *Why*: High performance on structured features (link counts, domain mismatches, special character ratios).
   - *Role*: Provides the primary classification based on the structural properties of the email.
2. **BERT (Transformers)**:
   - *Why*: Superior at understanding linguistic nuance and context.
   - *Role*: Detects subtle social engineering tactics and emotional triggers (urgency, fear, authority) that simple keyword scanners miss.
3. **Isolation Forest**:
   - *Why*: Excellent for unsupervised anomaly detection.
   - *Role*: Flags "Zero-Day" phishing patterns—emails that look significantly different from standard communication patterns.
4. **Threat Intelligence (TI) Integration**:
   - *Why*: Immediate blocking of known bad actors.
   - *Role*: Cross-references extracted domains against blacklists for instant critical alerts.

## 📦 Initial Setup & Local Deployment
To check out the project on your laptop, follow these steps:

### Option 1: Using Docker (Recommended)
1. Ensure you have [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) installed.
2. Clone the repository and navigate to the directory:
   ```bash
   git clone https://github.com/RAGULRAAJAN/Phishing-Detection-Legal-Risk-Classify.git
   cd Phishing-Detection-Legal-Risk-Classify
   ```
3. Run the application:
   ```bash
   docker-compose up --build
   ```
4. Access the **Frontend** at `http://localhost:8080` and the **API Docs** at `http://localhost:8000/docs`.

### Option 2: Manual Installation (Python)
1. **Backend**:
   ```bash
   cd backend
   python -m venv venv
   .\venv\Scripts\activate  # On Windows
   pip install -r requirements.txt
   python main.py
   ```
2. **Frontend**:
   - Open `frontend/index.html` directly in a browser or serve it using:
     ```bash
     cd frontend
     python -m http.server 8080
     ```

## ⚖️ Legal Mapping Engine
The system provides real-time compliance checks:
- **Identity Theft (IT Act 66C)**: Detection of credential harvesting.
- **Cheating by Personation (IT Act 66D)**: Identification of brand impersonation (e.g., Amazon, Banks).
- **Data Privacy (DPDP Act 2023 / GDPR)**: Detection of PII (Personally Identifiable Information) solicitation.
- **CCPA Violation Risk**: Monitoring for unauthorized exfiltration attempts of consumer data.

---
*Developed for advanced security triage and legal compliance monitoring.*
