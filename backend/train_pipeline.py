import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score
import torch
# from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
# from datasets import Dataset

def generate_mock_data(n_samples=1000):
    np.random.seed(42)
    # 0 = Ham, 1 = Phishing
    y = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])
    
    # Feature generation with some separability
    # subject_len, has_sender, num_attachments, PctExtHyperlinks, PctExtNullSelf..., FreqDomainMismatch, total_links
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
    
    return X, y

def train_random_forest(X, y_train, savedir="."):
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X, y_train)
    
    preds = rf.predict(X)
    print(f"RF Recall on training data (Low False Negatives!): {recall_score(y_train, preds):.2f}")
    
    # Save model and a background sample for LIME
    joblib.dump({
        "model": rf,
        "X_train_bg": X.sample(n=min(50, len(X)), random_state=42).values
    }, f"{savedir}/rf_model.pkl")
    print("RF model saved.")

def train_isolation_forest(X, savedir="."):
    print("Training Isolation Forest...")
    # Train only on 'Normal' (Ham) traffic in a real scenario, or mixed. 
    # Here we fit on X directly.
    model = IsolationForest(contamination=0.05, random_state=42)
    
    # Use only structural features
    structural_features = ["subject_len", "num_attachments", "total_links"]
    X_struct = X[structural_features]
    
    model.fit(X_struct)
    
    joblib.dump(model, f"{savedir}/if_model.pkl")
    print("Isolation Forest saved.")

def train_bert_mock(savedir="."):
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
    from datasets import Dataset
    print("Training/Initializing BERT...")
    model_name = "distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    # Generate tiny dataset for mock training (so we don't crash memory)
    texts = ["Please reset your password urgently via this link."] * 10 + ["Hello, let's catch up tomorrow for lunch."] * 10
    labels = [1] * 10 + [0] * 10
    
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
    
    # Fine tune swiftly
    trainer.train()
    
    # Save locally
    os.makedirs(f"{savedir}/bert_model_dir", exist_ok=True)
    tokenizer.save_pretrained(f"{savedir}/bert_model_dir")
    model.save_pretrained(f"{savedir}/bert_model_dir")
    print("BERT model saved.")

def load_real_data(csv_path):
    print(f"Loading real data from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # 0 = Ham, 1 = Phishing
    y = df["label"].values
    
    print("Extracting features from dataset records...")
    features_list = []
    
    from core.feature_extraction import extract_features_from_parts
    for idx, row in df.iterrows():
        # Columns: sender, receiver, date, subject, body, label, urls
        body = str(row.get("body", ""))
        subject = str(row.get("subject", ""))
        sender = str(row.get("sender", ""))
        
        # Use our unified feature extractor
        feat = extract_features_from_parts(sender, subject, body)
        features_list.append(feat)
        
        if idx % 1000 == 0 and idx > 0:
            print(f"  Processed {idx} records...")

    X = pd.DataFrame(features_list)
    return X, y

if __name__ == "__main__":
    print("--- Phishing ML Pipeline Bootstrapper ---")
    save_directory = "." 
    
    csv_file = "CEAS_08.csv"
    if os.path.exists(csv_file):
        # 1. Load Real data
        X_full, y = load_real_data(csv_file)
        # Separate body text for BERT, and structural features for RF
        X_structural = X_full.drop(columns=["body_text", "sender_email"])
        
        # 2. Train RF
        train_random_forest(X_structural, y, savedir=save_directory)
        
        # 3. Train IF
        train_isolation_forest(X_structural, savedir=save_directory)
        
        # 4. BERT (Optional - taking a subset for speed)
        # Uncomment below if you want to fine-tune BERT on real data
        # print("Training BERT on real data subset...")
        # (This would require more GPU/Time)
        
        # We call the mock/fast initialization to ensure the directory exists and weights are stable.
        train_bert_mock(save_directory)
        
    else:
        print(f"Real data {csv_file} not found. Falling back to mock data.")
        # 1. Gen mock data
        X_mock, y_mock = generate_mock_data(n_samples=500)
        # 2. RF
        train_random_forest(X_mock, y_mock, savedir=save_directory)
        # 3. IF
        train_isolation_forest(X_mock, savedir=save_directory)
    
    print("Pipeline training completed successfully!")
