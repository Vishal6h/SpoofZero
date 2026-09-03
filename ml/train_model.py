from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


texts = [
    # Phishing / suspicious
    "Urgent verify your account immediately or it will be suspended",
    "Your password has expired click here to login now",
    "Confirm your bank details immediately to avoid account closure",
    "You won a prize click this link to claim your reward",
    "Invoice overdue send payment immediately",
    "Security alert login to verify your identity",
    "Your mailbox storage is full verify your account now",
    "CEO requests urgent wire transfer payment",

    # Legitimate
    "Team meeting is scheduled for tomorrow at 10 AM",
    "Please find the project report attached",
    "Thank you for attending today's class",
    "Your order has been shipped successfully",
    "Reminder about our appointment next Monday",
    "Here are the notes from yesterday's meeting",
    "Your monthly statement is now available",
    "Please review the document when you have time",
]

labels = [
    1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0
]


vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2)
)

X = vectorizer.fit_transform(texts)

model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

model.fit(X, labels)


Path("ml").mkdir(exist_ok=True)

joblib.dump(
    vectorizer,
    "ml/vectorizer.joblib"
)

joblib.dump(
    model,
    "ml/phishing_model.joblib"
)

print("SpoofZero AI model trained successfully.")
print("Saved: ml/vectorizer.joblib")
print("Saved: ml/phishing_model.joblib")
