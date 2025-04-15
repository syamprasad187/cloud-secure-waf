import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle
import re
import os

def extract_features(request_data):
    features = {
        'path_length': len(request_data['path']),
        'has_suspicious_chars': int(any(c in request_data['path'] for c in '<>;"')),
        'header_count': len(request_data['headers']),
        'body_length': len(request_data['body']),
        'has_sql_keywords': int(bool(re.search(r'select|union|drop|insert', 
                                             request_data['body'].lower())))
    }
    return pd.DataFrame([features])

model_file = 'waf_model.pkl'
if os.path.exists(model_file):
    with open(model_file, 'rb') as f:
        model = pickle.load(f)
else:
    X = pd.DataFrame({
        'path_length': [10, 100, 15, 200],
        'has_suspicious_chars': [0, 1, 0, 1],
        'header_count': [5, 10, 6, 15],
        'body_length': [50, 500, 60, 1000],
        'has_sql_keywords': [0, 1, 0, 1]
    })
    y = [0, 1, 0, 1]
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    with open(model_file, 'wb') as f:
        pickle.dump(model, f)

def check_malicious_request(request_data):
    features = extract_features(request_data)
    prediction = model.predict(features)[0]
    return bool(prediction)