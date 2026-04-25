import sys
sys.path.append('.')
from core.ensemble import EnsembleAggregator
import pandas as pd

e = EnsembleAggregator('.')
e.initialize()

df = pd.read_csv('CEAS_08.csv')
ham = df[df['label'] == 0].head(10)
for idx, row in ham.iterrows():
    mock_eml = f"From: {row['sender']}\nSubject: {row['subject']}\n\n{row['body']}".encode('utf-8')
    res = e.analyze(mock_eml)
    print(f"Ham {idx} Score: {res['confidence']}")
