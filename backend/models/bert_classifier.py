import torch
# from transformers import AutoTokenizer, AutoModelForSequenceClassification

class BERTPhishingClassifier:
    def __init__(self, model_name="distilbert-base-uncased", local_path="bert_model_dir"):
        self.model_name = model_name
        self.local_path = local_path
        self.tokenizer = None
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.is_fine_tuned = False

    def load(self):
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        try:
            # Try to load locally fine-tuned model first
            import os
            if os.path.exists(self.local_path):
                self.tokenizer = AutoTokenizer.from_pretrained(self.local_path)
                self.model = AutoModelForSequenceClassification.from_pretrained(self.local_path)
                self.is_fine_tuned = True
            else:
                # Load default tokenizer and model (this acts as a mock out-of-the-box text classifier if not trained)
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name, num_labels=2)
                self.is_fine_tuned = False
            
            self.model.to(self.device)
            self.model.eval()
            return True
        except Exception as e:
            print(f"Warning: Could not load BERT model: {e}")
            return False

    def predict(self, text: str):
        if not self.model or not self.tokenizer or not text.strip():
            return 0.0

        if not self.is_fine_tuned:
            # If model is not fine-tuned, its classification head is random.
            # Return a neutral, low-threat score to avoid false positives.
            return 0.1

        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=False)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
            
            # Apply softmax to get probability for class 1 (Phishing)
            logits = outputs.logits
            probs = torch.nn.functional.softmax(logits, dim=-1)
            
            # Default model output for positive class
            score = probs[0][1].item()
            return score
        except Exception as e:
            print(f"BERT Error: {e}")
            return 0.0
