import os
import re
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.pipeline import Pipeline
from preprocess import preprocess_payload, shannon_entropy

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'cmd_model.joblib')

def _extract_features(text):
    t = preprocess_payload(text).lower()
    feats = {}
    feats['len'] = len(t)
    feats['entropy'] = shannon_entropy(t)
    feats['has_separators'] = int(bool(re.search(r'[;&|`]', t)))
    feats['has_download'] = int(bool(re.search(r'\b(wget|curl|powershell|nc|ncat)\b', t)))
    feats['has_path'] = int(bool(re.search(r'(/bin/|/etc/|\\\\windows\\\\|\\\\system32)', t)))
    feats['num_special'] = sum(1 for c in t if not c.isalnum() and not c.isspace())
    # token counts for common commands
    for tok in ('rm','cat','wget','curl','nc','bash','powershell','python'):
        feats[f'tok_{tok}'] = int(tok in t)
    return feats

class CmdModel:
    def __init__(self, pipeline):
        self.pipeline = pipeline

    def predict(self, payload):
        x = _extract_features(payload)
        y = self.pipeline.predict([x])[0]
        return 'cmd_injection' if y == 1 else 'benign'

def train_cmd_model(dataset_path, out_path=MODEL_PATH):
    import csv
    X = []
    y = []
    if not os.path.isfile(dataset_path):
        raise FileNotFoundError(dataset_path)
    with open(dataset_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            payload = r.get('payload','')
            label = r.get('label','benign').lower()
            lbl = 1 if 'cmd' in label or 'command' in label else 0
            X.append(_extract_features(payload))
            y.append(lbl)
    vec = DictVectorizer(sparse=False)
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    pipeline = Pipeline([('vec', vec), ('clf', clf)])
    pipeline.fit(X, y)
    joblib.dump(pipeline, out_path)
    return CmdModel(pipeline)

def load_cmd_model(path=MODEL_PATH):
    if not os.path.isfile(path):
        return None
    pipeline = joblib.load(path)
    return CmdModel(pipeline)