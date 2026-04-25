import sys
sys.path.append('.')
from models.bert_classifier import BERTPhishingClassifier

b = BERTPhishingClassifier(local_path='bert_model_dir')
b.load()
print(f"Fine-tuned: {b.is_fine_tuned}")
score = b.predict("New device login detected in your Flipkart account")
print(f"BERT Score for Flipkart Subject: {score}")

score2 = b.predict("Hi Ragul, a new login was detected on your account. Please click here to verify.")
print(f"BERT Score for Phishing-like Body: {score2}")
