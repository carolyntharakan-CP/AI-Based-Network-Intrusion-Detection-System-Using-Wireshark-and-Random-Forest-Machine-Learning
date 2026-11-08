import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

print("Loading dataset...")

df = pd.read_csv(
    r"C:\Users\carol\OneDrive\Documents\AI_IDS_Project\cleaned_dataset.csv"
)

# Take a random sample of 100000 rows
df = df.sample(n=100000, random_state=42)

features = [
    'Flow Duration',
    'Dst Port',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Packet Length Mean',
    'Average Packet Size'
]

df = df[features + ['Label']]

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

X = df[features]
y = df['Label']

print("Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

print("Training Random Forest Model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Testing Model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nAccuracy =", accuracy)

print("\nClassification Report:\n")
print(classification_report(y_test, predictions))

joblib.dump(
    model,
    r"C:\Users\carol\OneDrive\Documents\AI_IDS_Project\ids_model.pkl"
)

print("\nModel Saved Successfully!")