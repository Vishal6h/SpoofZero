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


def train_legacy_demo(output_directory):
    """Reproduce the 16-example demonstration only into a new separate directory."""
    destination = Path(output_directory).resolve()
    root = Path(__file__).resolve().parent
    if destination == root or root in destination.parents and destination.name == "legacy_demo":
        raise ValueError("The active legacy artifacts and metadata are protected")
    destination.mkdir(parents=True, exist_ok=False)
    vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2))
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(vectorizer.fit_transform(texts), labels)
    joblib.dump(vectorizer, destination / "vectorizer.joblib")
    joblib.dump(model, destination / "phishing_model.joblib")


if __name__ == "__main__":
    # Support both module execution and this file's direct path, without training
    # or writing anything merely because another module imports this one.
    import sys
    if not __package__:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from ml.experiment import main
    main()
