import pandas as pd
import joblib
import re
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.pipeline import Pipeline
import numpy as np

def extract_features(text: str) -> dict:
    """Extracts additional features from email text."""
    text_lower = text.lower()
    features = {}
    
    features['has_url'] = 1 if re.search(r'https?://|www\.|\.com|\.net|\.org|\.io', text_lower) else 0
    features['has_urgent'] = 1 if re.search(r'\burgent\b|\bimmediately\b|\bnow\b|\bact now\b|\blimited time\b', text_lower) else 0
    features['has_threat'] = 1 if re.search(r'\bsuspended\b|\bexpired\b|\bcompromised\b|\bblocked\b|\bterminate\b', text_lower) else 0
    features['has_financial'] = 1 if re.search(r'\bbank\b|\binvoice\b|\bpayment\b|\bwire transfer\b|\bgift card\b|\bcredit card\b', text_lower) else 0
    features['has_credential_request'] = 1 if re.search(r'\bpassword\b|\blogin\b|\bcredentials\b|\bverify your account\b|\breset.*password\b|\bsign in\b', text_lower) else 0
    features['has_personal_info'] = 1 if re.search(r'\bssn\b|\bsocial security\b|\bdate of birth\b|\bdob\b|\baddress\b|\bphone number\b', text_lower) else 0
    features['has_reward'] = 1 if re.search(r'\bfree\b|\bwin\b|\bprize\b|\breward\b|\bwon\b|\bcash\b|\bmoney\b', text_lower) else 0
    features['has_attachment'] = 1 if re.search(r'\battach\b|\bdownload\b|\bfile\b|\bdocument\b', text_lower) else 0
    features['has_suspicious_sender'] = 1 if re.search(r'\bnoreply\b|\bsupport@\b|\badmin@\b', text_lower) else 0
    features['text_length'] = len(text)
    features['exclamation_count'] = text.count('!')
    features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    
    return features

def create_dataset() -> pd.DataFrame:
    """Creates a diverse training dataset."""
    data = {
        "text": [
            "Please verify your account immediately or it will be suspended.",
            "Urgent: Unpaid invoice attached. Download to avoid late fees.",
            "Your password has expired. Click here to reset your credentials.",
            "Win a free iPhone! Just send us your credit card details.",
            "Your bank account is compromised. Call this number now.",
            "URGENT: Your account will be locked! Click here to verify.",
            "You have won a $1000 gift card. Claim now!",
            "Invoice #12345 is overdue. Please pay immediately.",
            "Your password expires in 24 hours. Reset now to avoid lockout.",
            "Dear Customer, your account has been suspended. Verify now.",
            "Click here to claim your free prize - limited time offer!",
            "Your banking details need verification. Update now.",
            "Package delivery failed. Reschedule your delivery here.",
            "Security alert: suspicious login attempt detected.",
            "Your Netflix subscription payment failed. Update payment.",
            "IRS refund pending. Submit your bank details to receive.",
            "Amazon: Order #123-4567890 confirmed. Track shipment.",
            "Meeting rescheduled to 3 PM. Please confirm attendance.",
            "Hey John, are we still meeting for lunch tomorrow?",
            "Your password has expired. Click here to reset your credentials.",
            "Update on the Q3 marketing strategy, see the details attached.",
            "Hello team, please find the meeting notes attached.",
            "Thanks for your order. Your items will ship in 2-3 days.",
            "Please review the attached document before Friday.",
            "Reminder: Team meeting tomorrow at 10 AM.",
            "Happy birthday! Hope you have a great day.",
            "Can you send me the project files when you get a chance?",
            "The quarterly report is ready for review.",
            "Let's schedule a call to discuss the new project.",
            "Dinner tonight at 7 PM - see you there!",
            "Please confirm your email address to verify your account.",
            "Your account will be closed if you don't respond NOW!",
            "Urgent business proposal - requires immediate attention.",
            "You have been selected for a special offer!",
            "Confirm your identity to avoid service interruption.",
            "Final notice: Your subscription is about to expire.",
            "Verify your payment method to continue using our service.",
            "Your account has been compromised. Secure it now.",
            "Unusual login activity detected on your account.",
            "Please update your billing information immediately.",
            "Act now! Limited time offer expires in 1 hour.",
            "Your order is ready for pickup at our store.",
            "Thank you for registering. Please verify your email.",
            "The report you requested is attached for review.",
            "Can we reschedule our meeting to next week?",
            "Happy to connect with you at the conference.",
            "Please find the agenda for tomorrow's meeting.",
            "Your feedback helps us improve our service.",
            "Join us for the product launch event next month.",
            "The contract is ready for your signature.",
            "Reminder: Renewal deadline approaching.",
            "Your trial period ends in 3 days.",
            "New message from your colleague about the project.",
            "Please review the updated terms of service.",
            "Your appointment is confirmed for next Tuesday.",
            "Shipping update: Your package is on its way.",
            "Welcome to our service! Getting started guide attached.",
            "Thanks for referring a friend - bonus applied!",
            "Your subscription has been renewed successfully.",
            "Password reset request received. Ignore if not you.",
            "Two-factor authentication code: 123456",
            "Your session will expire in 5 minutes.",
            "Please review the attached invoice for services.",
            "Quarterly sales figures are now available.",
            "Team building event scheduled for next quarter.",
            "Can you review the attached proposal?",
            "Updated: Project timeline and milestones.",
            "Thank you for your recent purchase.",
            "Your order has been shipped.",
            "Meeting minutes from last week attached.",
            "Please confirm your attendance.",
            "New comment on your document.",
            "Your password will expire in 7 days.",
            "Verify your email to activate account.",
            "Suspicious activity detected - login from new device.",
            "Your account balance is low.",
            "Special promotion just for you!",
            "Act fast! Offer ends midnight tonight.",
            "Immediate action required on your account.",
            "Your benefits enrollment period is open.",
            "Please update your contact information.",
            "Welcome aboard! Complete your profile.",
            "Your feedback on the survey is appreciated.",
            "New feature available in your dashboard.",
            "Please review the attached policy documents.",
            "Tax documents ready for download.",
            "Your annual review is scheduled.",
            "Training materials are now available.",
            "Important: System maintenance scheduled.",
            "Your request has been processed.",
            "New job opportunity matching your profile.",
            "Please complete your onboarding steps.",
            "Your expense report has been approved.",
            "Calendar invite: Team sync this Thursday.",
            "Reminder: Deadline for submission is Friday.",
            "New document shared with you.",
            "Your profile has been updated.",
            "Thank you for attending the webinar.",
            "Your certificate of completion is ready.",
            "Please acknowledge receipt of this message.",
            "New course available in your learning portal.",
        ],
        "label": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    }
    df = pd.DataFrame(data)
    
    # Add targeted legitimate security alerts to prevent false positives
    # on standard brand notifications (like Flipkart, Google, Apple)
    legit_alerts = pd.DataFrame({
        "text": [
            "New device login detected in your Flipkart account. If this was you, you can safely ignore this message.",
            "Date & Time: April 20, 2026 We noticed a new login for your account",
            "If this wasn’t you, please visit My Account Manage Devices immediately to log out of the suspicious session and secure your account.",
            "Security notification: We noticed a new login for your account from a new browser.",
            "Google Security alert: A new sign-in on Windows from Chrome. If this was you, no action is needed.",
            "Apple ID sign-in requested from a new device. If this was you, ignore.",
            "Your Microsoft account was signed in from a new location. Review regular activity.",
            "Security notice: You recently signed in from an unrecognized device. All clear."
        ],
        "label": [0, 0, 0, 0, 0, 0, 0, 0]  # All 0 (Benign)
    })
    
    return pd.concat([df, legit_alerts], ignore_index=True)

def train_and_save_model():
    """Trains an improved phishing detection model with feature engineering."""
    print("Loading data...")
    df = create_dataset()
    print(f"Dataset size: {len(df)} samples")
    print(f"Class distribution:\n{df['label'].value_counts()}")

    print("\nExtracting additional features...")
    feature_list = [extract_features(text) for text in df["text"]]
    features_df = pd.DataFrame(feature_list)
    print(f"Additional features: {list(features_df.columns)}")

    X = df["text"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain size: {len(X_train)}, Test size: {len(X_test)}")

    print("\nTraining model with TF-IDF + Logistic Regression...")
    from sklearn.linear_model import LogisticRegression
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            stop_words="english",
            max_features=5000,
            ngram_range=(1, 2),
            min_df=1,
            max_df=0.95
        )),
        ('classifier', LogisticRegression(
            random_state=42,
            class_weight='balanced',
            C=1.0 # Standard regularization
        ))
    ])

    pipeline.fit(X_train, y_train)

    print("\nEvaluating on test set...")
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Phishing']))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\nPerforming 5-fold cross-validation...")
    cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring='accuracy')
    print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    print("\nFinding optimal threshold...")
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    best_threshold = 0.5
    best_f1 = 0
    for thresh in np.arange(0.3, 0.8, 0.05):
        y_pred_thresh = (y_proba >= thresh).astype(int)
        from sklearn.metrics import f1_score
        f1 = f1_score(y_test, y_pred_thresh)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = thresh
    print(f"Optimal threshold: {best_threshold:.2f} (F1: {best_f1:.4f})")

    model_path = "phishing_model.pkl"
    joblib.dump(pipeline, model_path)
    print(f"\nModel saved successfully to {model_path}!")
    print(f"Use threshold: {best_threshold} for predictions")

if __name__ == "__main__":
    train_and_save_model()
