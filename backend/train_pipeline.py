import os
import joblib
import pandas as pd
import numpy as np
import json
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score
import torch

def generate_mock_data(n_samples=1000):
    np.random.seed(42)
    # 0 = Ham, 1 = Phishing
    y = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])
    
    # Feature generation with some separability
    X = pd.DataFrame({
        "subject_len": np.where(y == 1, np.random.normal(50, 20, n_samples), np.random.normal(30, 10, n_samples)).astype(int),
        "has_sender": np.where(y == 1, np.random.choice([0, 1], p=[0.2, 0.8], size=n_samples), 1),
        "num_attachments": np.where(y == 1, np.random.poisson(lam=1.5, size=n_samples), np.random.poisson(lam=0.2, size=n_samples)),
        "PctExtHyperlinks": np.where(y == 1, np.random.beta(5, 2, n_samples), np.random.beta(2, 5, n_samples)),
        "PctExtNullSelfRedirectHyperlinksRT": np.where(y == 1, np.random.beta(6, 2, n_samples), np.random.beta(1, 6, n_samples)),
        "FrequentDomainNameMismatch": np.where(y == 1, np.random.choice([1, 0], p=[0.8, 0.2], size=n_samples), np.random.choice([1, 0], p=[0.1, 0.9], size=n_samples)),
        "total_links": np.random.poisson(lam=5, size=n_samples)
    })
    
    X["subject_len"] = X["subject_len"].clip(lower=0)
    X["body_text"] = "Sample email body for training." # Dummy for structural merge
    
    return X, y

def train_random_forest(X, y_train, savedir="."):
    print("Training Random Forest...")
    # Drop non-structural columns if present
    X_train = X.drop(columns=["body_text", "sender_email", "extracted_domains"], errors='ignore')
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    
    preds = rf.predict(X_train)
    print(f"RF Recall on training data: {recall_score(y_train, preds):.2f}")
    
    # Save model and a background sample for LIME
    joblib.dump({
        "model": rf,
        "X_train_bg": X_train.sample(n=min(50, len(X_train)), random_state=42).values
    }, f"{savedir}/rf_model.pkl")
    print("RF model saved.")

def train_isolation_forest(X, savedir="."):
    print("Training Isolation Forest...")
    model = IsolationForest(contamination=0.05, random_state=42)
    
    # Use only structural features
    structural_features = ["subject_len", "num_attachments", "total_links"]
    # Ensure columns exist, if not fallback to whatever structural features we have
    available = [f for f in structural_features if f in X.columns]
    X_struct = X[available]
    
    model.fit(X_struct)
    
    joblib.dump(model, f"{savedir}/if_model.pkl")
    print("Isolation Forest saved.")

def train_bert(texts, labels, savedir=".", is_mock=True):
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
    from datasets import Dataset
    print(f"Training BERT ({'Mock' if is_mock else 'Active Learning Update'})...")
    model_name = "distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    encodings = tokenizer(texts, truncation=True, padding=True, return_tensors='pt')
    dataset = Dataset.from_dict({
        "input_ids": encodings["input_ids"],
        "attention_mask": encodings["attention_mask"],
        "labels": torch.tensor(labels)
    })
    
    training_args = TrainingArguments(
        output_dir='./results',
        num_train_epochs=1,
        per_device_train_batch_size=4,
        save_strategy='no',
        logging_steps=5,
        no_cuda=not torch.cuda.is_available()
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
    )
    
    trainer.train()
    
    os.makedirs(f"{savedir}/bert_model_dir", exist_ok=True)
    tokenizer.save_pretrained(f"{savedir}/bert_model_dir")
    model.save_pretrained(f"{savedir}/bert_model_dir")
    print("BERT model saved.")

def load_feedback_data():
    feedback_path = "logs/feedback_retraining.jsonl"
    if not os.path.exists(feedback_path):
        return None, None
    
    print(f"Loading active learning feedback from {feedback_path}...")
    texts = []
    labels = []
    
    with open(feedback_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                data = json.loads(line)
                texts.append(data["original_text"])
                labels.append(1 if data["is_phishing_actually"] else 0)
            except:
                continue
            
    if not texts:
        return None, None
        
    print(f"  Extracted {len(texts)} feedback records.")
    
    from core.feature_extraction import extract_features_from_parts, extract_features_from_eml
    features_list = []
    for text in texts:
        try:
            if "From:" in text[:500] and "Subject:" in text[:500]:
                feat = extract_features_from_eml(text.encode('utf-8'))
            else:
                feat = extract_features_from_parts("internal@local", "Subject", text)
            features_list.append(feat)
        except Exception as e:
            print(f"  Warning: Skipping malformed feedback record: {e}")
            continue
        
    if not features_list:
        return None, None

    X_fb = pd.DataFrame(features_list)
    y_fb = np.array(labels[:len(features_list)])
    return X_fb, y_fb

def load_real_data(csv_path):
    print(f"Loading real data from {csv_path}...")
    df = pd.read_csv(csv_path)
    # Check for label column
    if "label" not in df.columns:
        print(f"  Error: 'label' column missing in {csv_path}")
        return None, None

    y = df["label"].values
    
    features_list = []
    from core.feature_extraction import extract_features_from_parts
    for idx, row in df.iterrows():
        body = str(row.get("body", ""))
        subject = str(row.get("subject", ""))
        sender = str(row.get("sender", ""))
        feat = extract_features_from_parts(sender, subject, body)
        features_list.append(feat)
        if idx % 1000 == 0 and idx > 0:
            print(f"  Processed {idx} records...")

    X = pd.DataFrame(features_list)
    return X, y

if __name__ == "__main__":
    print("--- Phishing ML Pipeline Bootstrapper (Active Learning Enabled) ---")
    save_directory = "." 
    
    # 1. Base Data Loading
    csv_file = "CEAS_08.csv"
    X_base, y_base = None, None
    if os.path.exists(csv_file) and os.path.getsize(csv_file) > 1000: # Simple LFS check
        X_base, y_base = load_real_data(csv_file)
    
    if X_base is None:
        print(f"Real data not available or malformed. Using mock base data.")
        X_base, y_base = generate_mock_data(n_samples=500)

    # 2. Feedback Data Loading (Active Learning Loop)
    X_fb, y_fb = load_feedback_data()
    
    if X_fb is not None:
        print("Merging feedback data into training set...")
        # Ensure columns match for concatenation
        # We only strictly need the structural features and body_text for BERT
        X_full = pd.concat([X_base, X_fb], ignore_index=True)
        y_full = np.concatenate([y_base, y_fb])
    else:
        X_full, y_full = X_base, y_base

    # 3. Train RF & IF
    train_random_forest(X_full, y_full, savedir=save_directory)
    train_isolation_forest(X_full, savedir=save_directory)

    # 4. Train BERT
    if "body_text" in X_full.columns:
        bert_texts = X_full["body_text"].tolist()
        bert_labels = y_full.tolist()
        # Keep training set small for speed in this environment
        train_bert(bert_texts[:100], bert_labels[:100], savedir=save_directory, is_mock=False)
    else:
        train_bert(["Mock text"]*10, [0]*10, savedir=save_directory, is_mock=True)
    
    print("Pipeline training completed successfully with Active Learning data!")
