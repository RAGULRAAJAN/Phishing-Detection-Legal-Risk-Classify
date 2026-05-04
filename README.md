# Phishing Detection & Legal Risk Classification System (Hybrid ML Pipeline)

An enterprise-grade security solution for analyzing phishing emails and mapping them to legal compliance frameworks. This system combines multiple machine learning architectures for high-accuracy threat detection with a rule-based engine to identify potential legal violations.

## 🌟 Core Idea
The project addresses the gap between **technical threat detection** and **legal accountability**. While most systems only identify if an email is phishing, this system explains *why* it is dangerous and *which laws* the attacker is violating (e.g., IT Act, DPDP Act, GDPR), providing SOC analysts with immediate actionable intelligence.

## 🚀 Key Upgrades & Features
We have significantly enhanced the system with the following upgrades:
- **Hybrid Ensemble Architecture**: Integrated a multi-model voting system combining Random Forest, BERT, and Isolation Forest.
- **Deep Semantic Analysis**: Leveraged transformer-based NLP (BERT) to detect subtle social engineering.
- **Automated Legal Mapping**: Translates technical threat indicators into specific legal sections (e.g., Section 66C/66D of the IT Act).
- **Real-Time Active Learning Loop**: 
    - **Human-in-the-Loop Feedback**: Analysts can flag emails via `/api/v1/feedback`.
    - **Instant Override**: Corrections are applied immediately via a real-time override mechanism.
    - **Automated Retraining**: The `train_pipeline.py` script now consumes analyst feedback to retrain ML models, ensuring the system evolves with new threats.
- **Sandboxed Link Preview**: Safely fetch and inspect link metadata without risking the user's environment.
- **SIEM-Ready Logging**: Structured JSON logs optimized for ingestion into Splunk or ELK.

## 🧠 Machine Learning Models
1. **Random Forest (RF)**: Primary classification based on structural properties (links, domains).
2. **BERT (Transformers)**: Superior at understanding linguistic nuance and emotional triggers.
3. **Isolation Forest**: Flags "Zero-Day" phishing patterns via unsupervised anomaly detection.

## 📦 Local Deployment

### Manual Installation (Python)
1. **Backend**:
   ```bash
   cd backend
   python -m venv venv
   .\venv\Scripts\activate  # On Windows
   pip install -r requirements.txt
   python train_pipeline.py # Initializes models with base + feedback data
   python main.py
   ```
2. **Frontend**:
   - Open `frontend/index.html` in a browser or use:
     ```bash
     cd frontend
     python -m http.server 8080
     ```

## ⚖️ Legal Mapping Engine
- **Identity Theft (IT Act 66C)**: Detection of credential harvesting.
- **Cheating by Personation (IT Act 66D)**: Identification of brand impersonation.
- **Data Privacy (DPDP Act 2023 / GDPR)**: Detection of PII solicitation.
