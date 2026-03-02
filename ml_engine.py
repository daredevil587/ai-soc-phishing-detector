import joblib
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

MODEL_FILE = "phishing_model.pkl"
VECTORIZER_FILE = "vectorizer.pkl"
ACCURACY_FILE = "model_accuracy.pkl"


def train_demo_model():
    # Simple demo dataset
    texts = [
        "Your account has been suspended verify immediately",
        "Urgent payment required click this link",
        "Invoice attached for your review",
        "Meeting scheduled for tomorrow",
        "Your bank account is blocked verify now",
        "Lunch tomorrow?",
        "Project update attached",
        "Reset your password immediately"
    ]

    labels = [1, 1, 1, 0, 1, 0, 0, 1]  # 1 = phishing, 0 = safe

    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(texts)

    model = LogisticRegression()
    model.fit(X, labels)

    # Calculate training accuracy
    predictions = model.predict(X)
    accuracy = accuracy_score(labels, predictions)

    # Save everything
    joblib.dump(model, MODEL_FILE)
    joblib.dump(vectorizer, VECTORIZER_FILE)
    joblib.dump(accuracy, ACCURACY_FILE)


def load_model():
    if not os.path.exists(MODEL_FILE):
        train_demo_model()

    model = joblib.load(MODEL_FILE)
    vectorizer = joblib.load(VECTORIZER_FILE)

    return model, vectorizer


def predict_phishing(text):
    model, vectorizer = load_model()
    X = vectorizer.transform([text])
    probability = model.predict_proba(X)[0][1]  # phishing probability
    return probability


def get_model_accuracy():
    if not os.path.exists(ACCURACY_FILE):
        train_demo_model()

    return joblib.load(ACCURACY_FILE)