# Phishing Detection & Legal Risk Classification System

An enterprise-grade security solution for analyzing phishing emails and mapping them to legal compliance frameworks. This system combines machine learning for threat detection with a rule-based engine to identify potential legal violations under the Information Technology Act and DPDP Act.

## 🚀 Working Flow

The application follows a structured analysis pipeline from ingestion to risk reporting:

1.  **Ingestion Phase**:
    *   The user interacts with a high-density, professional frontend (HTML/JS).
    *   Supports direct text input or file upload (Drag & Drop) of `.eml` files.
    *   Frontend parses `.eml` files locally to extract headers and body.

2.  **Analysis Phase**:
    *   The frontend sends the payload to a **FastAPI-based Backend**.
    *   **ML Detection**: The backend utilizes a pre-trained Scikit-learn model (`phishing_model.pkl`) to calculate a **Threat Score** based on linguistic patterns and threat indicators.
    *   **Legal Risk Evaluation**: The `legal_engine.py` processes the content to map risks to specific legal sections:
        *   **IT Act Section 66C**: Identity Theft.
        *   **IT Act Section 66D**: Cheating by Personation.
        *   **DPDP Act 2023**: Data Privacy and PII exposure risks.

3.  **Logging & Monitoring**:
    *   Every analysis event is logged into `backend/logs/security_events.log` in structured JSON format.
    *   Designed for seamless ingestion into SIEM platforms like **Splunk** or **ELK Stack** for SOC monitoring.

4.  **Reporting Phase**:
    *   The frontend dynamically renders the results:
        *   **Threat Meter**: Visual percentage of the calculated risk.
        *   **Status Indicators**: "SAFE", "WARNING", or "CRITICAL" based on configurable thresholds.
        *   **Risk Tags**: Categorized indicators (e.g., "Urgent Language", "Link Manipulation").
        *   **Legal Expanders**: Detailed legal context for each detected violation.

## 🛠️ Technology Stack

*   **Frontend**: Vanilla HTML5, CSS3 (Glassmorphism design), JavaScript (ES6+).
*   **Backend**: Python, FastAPI, Uvicorn, Scikit-learn, joblib.
*   **Deployment**: Docker & Docker Compose for containerization.
*   **Logging**: Structured JSON logging for SIEM integration.

## 📦 Local Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/RAGULRAAJAN/Phishing-Detection-Legal-Risk-Classify.git
    cd Phishing-Detection-Legal-Risk-Classify
    ```

2.  **Using Docker (Recommended)**:
    ```bash
    docker-compose up --build
    ```
    *   Frontend: `http://localhost:8080`
    *   Backend: `http://localhost:8000`

3.  **Manual Installation**:
    *   **Backend**: `pip install -r backend/requirements.txt` && `python backend/main.py`
    *   **Frontend**: Serve `frontend/` directory using any web server (e.g., `python -m http.server 8080`).

## ⚖️ Legal Mapping Engine

The system is designed to provide security analysts with immediate legal context:
*   **Identity Theft**: Detection of spoofing and credential harvesting.
*   **Personation**: Identification of fraudulent impersonation of trusted brands.
*   **Data Protection**: Detection of attempts to solicit PII (SSN, DOB, etc.) in violation of data privacy laws.

---
*Developed for advanced security triage and legal compliance monitoring.*
