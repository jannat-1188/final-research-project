import re
import time
from pathlib import Path
from datetime import datetime
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# ============================================================
# PROJECT PATH
# ============================================================
BASE_PATH = Path(__file__).resolve().parent
RAW_DATA = BASE_PATH / "Data" / "raw"
if not RAW_DATA.exists():
    RAW_DATA = BASE_PATH

print("=" * 70)
print("AI PHISHING PREVENTION SYSTEM")
print("=" * 70)
# ============================================================
# TEXT CLEANING / LABEL CONVERSION
# ============================================================
def clean_text(value):
    # Some CSVs can contain duplicate column names; handle non-scalar values safely.
    if isinstance(value, pd.Series):
        value = " ".join(value.dropna().astype(str).tolist())
    if isinstance(value, (list, tuple)):
        value = " ".join(map(str, value))
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass

    value = str(value).lower()
    value = re.sub(r"http\S+|www\S+", " URL ", value)
    value = re.sub(r"\S+@\S+", " EMAIL ", value)
    value = re.sub(r"[^a-zA-Z0-9 ]", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def convert_label(value):
    # Return None for unknown labels instead of incorrectly marking them safe.
    if isinstance(value, pd.Series):
        value = value.dropna().astype(str).iloc[0] if not value.dropna().empty else ""
    label = str(value).lower().strip()

    phishing_labels = {
        "1", "spam", "phishing", "scam", "fraud", "fake", "malicious",
        "junk", "phishing email", "spam email"
    }
    safe_labels = {
        "0", "ham", "legitimate", "safe", "real", "not spam",
        "legitimate email", "safe email"
    }

    if label in phishing_labels or any(
        term in label for term in ("phishing", "scam", "fraud", "malicious")
    ):
        return 1
    if label in safe_labels or label.startswith("ham"):
        return 0
    if label.startswith("spam") or label == "1.0":
        return 1
    if label in {"0.0"}:
        return 0
    return None


# ============================================================
# DATASET LOADING (only show the total dataset count)
# ============================================================
dataset_order = [
    "sms_benchmark.tsv",
    "kaggle_phishing_emails.csv",
    "dataset.csv",
    "Phishing_Email.csv",
    "Phishing_validation_emails.csv",
    "spam.csv",
    "spam_ham_dataset.csv",
]
texts, labels = [], []
total = 0

TEXT_NAMES = (
    "text", "message", "email", "content", "body", "subject", "v2"
)
LABEL_NAMES = (
    "label", "class", "category", "type", "target", "v1"
)


def choose_column(columns, candidates, exclude=None):
    exclude = set(exclude or [])
    normalized = {col: re.sub(r"[^a-z0-9]", "", str(col).lower()) for col in columns}
    # Prefer exact matches, then names containing a candidate.
    for candidate in candidates:
        for col, norm in normalized.items():
            if col not in exclude and norm == candidate:
                return col
    for candidate in candidates:
        for col, norm in normalized.items():
            if col not in exclude and candidate in norm:
                return col
    return None
for filename in dataset_order:
    path = RAW_DATA / filename
    if not path.exists():
        continue

    try:
        if str(path).endswith('.tsv'):
            df = pd.read_csv(path, sep='	', header=None, names=['label', 'message'])
        else:
            try:
                df = pd.read_csv(path, encoding="utf-8-sig", on_bad_lines="skip")
            except (UnicodeDecodeError, pd.errors.ParserError):
                df = pd.read_csv(path, encoding="latin-1", on_bad_lines="skip")

        if df.empty:
            continue

        # Normalize duplicate/odd column names for robust matching.
        text_col = choose_column(df.columns, TEXT_NAMES)
        label_col = choose_column(df.columns, LABEL_NAMES, exclude=[text_col] if text_col else [])

        # Common public datasets sometimes use different names.
        if text_col is None and len(df.columns) >= 2:
            text_col = df.columns[-1]
        if label_col is None and len(df.columns) >= 2:
            possible = [c for c in df.columns if c != text_col]
            label_col = possible[0] if possible else None

        if text_col is None or label_col is None:
            continue

        # Duplicate column names may return a DataFrame; select the first matching column.
        text_data = df.loc[:, text_col]
        label_data = df.loc[:, label_col]
        if isinstance(text_data, pd.DataFrame):
            text_data = text_data.iloc[:, 0]
        if isinstance(label_data, pd.DataFrame):
            label_data = label_data.iloc[:, 0]

        temp = pd.DataFrame({"text": text_data, "label": label_data}).dropna()
        temp["text"] = temp["text"].apply(clean_text)
        temp["label"] = temp["label"].apply(convert_label)
        temp = temp[(temp["text"] != "") & temp["label"].notna()]

        texts.extend(temp["text"].tolist())
        labels.extend(temp["label"].astype(int).tolist())
        total += len(temp)

    except Exception:
        # Ignore a malformed/unreadable file and continue with other datasets.
        continue

print(f"\nTotal Dataset Samples : {total}")


# ============================================================
# TRAIN AI MODEL
# ============================================================
if total < 10 or len(set(labels)) < 2:
    raise RuntimeError(
        "Not enough usable labelled data to train the model. "
        "Check the CSV text and label columns in Data/raw."
    )

# Split only when each class has enough examples.
X_train, X_test, y_train, y_test = train_test_split(
    texts,
    labels,
    test_size=0.20,
    random_state=42,
    stratify=labels,
)
vectorizer = TfidfVectorizer(
    max_features=8000,
    ngram_range=(1, 2),
    stop_words="english",
    min_df=2,
    sublinear_tf=True,
)
X_train_vec = vectorizer.fit_transform(X_train)

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    random_state=42,
)
model.fit(X_train_vec, y_train)


# ============================================================
# USER INPUT
# ============================================================
print("\n" + "=" * 70)
print("SELECT MESSAGE TYPE")
print("=" * 70)
print("1. Email")
print("2. SMS")

while True:
    choice = input("\nEnter Choice (1/2): ").strip()
    if choice in {"1", "2"}:
        break
    print("Invalid choice. Try again.")


if choice == "1":
    MESSAGE_TYPE = "EMAIL"
    sender = input("\nSender Email : ").strip()
    subject = input("Subject      : ").strip()
    message = input("Message Body : ").strip()
    link = input("Email URL / Link (optional): ").strip()
    attachment = input("Attachment Name (optional): ").strip()

else:
    MESSAGE_TYPE = "SMS"
    sender = input("\nPhone Number : ").strip()
    subject = ""
    message = input("SMS Content  : ").strip()
    link = input("SMS URL / Link (optional): ").strip()
    attachment = ""

try:
   
    amount_input = input("Transaction Amount (BDT, optional): ").strip()

    amount = float(amount_input) if amount_input else 0.0
    if amount < 0:
        amount = 0.0
except ValueError:
    amount = 0.0

print("\n" + "=" * 70)
print("STARTING MULTI-LAYER PHISHING PREVENTION")
print("=" * 70)

layer_result = {}
risk_score = 0
sender_lower = sender.lower().strip()

combined = (subject + " " + message + " " + link).lower()

full_message = (
    sender + " " + subject + " " + message + " " + link
).lower()

# ============================================================
# LAYER 1: SENDER & HEADER AUTHENTICATION
# ============================================================
print("\n[LAYER 1] Sender & Header Authentication")
time.sleep(0.5)

header_flags = []
email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

if MESSAGE_TYPE == "EMAIL":
    if not re.match(email_pattern, sender):
        header_flags.append("Invalid or unusual sender email format")
    domain = sender_lower.rsplit("@", 1)[-1] if "@" in sender_lower else ""
    suspicious_domain_terms = (
        "verify-account", "security-update", "bank-login", "freegift",
        "secure-login", "account-alert", "paypa1", "gmai1"
    )
    if any(term in domain for term in suspicious_domain_terms):
        header_flags.append("Lookalike or suspicious sender domain")
    # Public email providers are not proof that a sender is trustworthy.
    if domain in {"", "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com"}:
        header_flags.append("Sender domain cannot be independently authenticated in this offline demo")
else:
    digits = re.sub(r"\D", "", sender)
    if len(digits) < 7:
        header_flags.append("Unusual phone number format")

if any("Lookalike" in flag or "Invalid" in flag or "Unusual phone" in flag for flag in header_flags):
    layer_result["Layer 1"] = "WARNING"
    risk_score += 20
    print("WARNING : " + "; ".join(header_flags))
elif header_flags:
    layer_result["Layer 1"] = "WARNING"
    risk_score += 5
    print("WARNING : " + "; ".join(header_flags))
else:
    layer_result["Layer 1"] = "PASS"
    print("PASS : Sender format looks normal (identity is not externally verified).")


# ============================================================
# LAYER 2: BEHAVIORAL ANOMALY DETECTION
# ============================================================
print("\n[LAYER 2] Behavioral Anomaly Detection")
time.sleep(0.5)

high_risk_phrases = [
    "urgent", "verify your account", "verify account", "reset your password",
    "password", "otp", "one time password", "account suspended",
    "account emergency", "unusual activity", "click immediately",
    "act now", "limited time", "claim your prize", "winner",
    "confirm your identity", "login from", "if it's not you",
    "if it is not you", "send code", "share the code", "bank account",
    "bKash", "nagad", "wallet", "payment failed", "update payment",
]
behavior_score = sum(1 for phrase in high_risk_phrases if phrase in combined)

if datetime.now().hour >= 23 or datetime.now().hour <= 5:
    behavior_score += 1
    print("Warning : Message checked during off-hours.")

if behavior_score >= 4:
    layer_result["Layer 2"] = "HIGH RISK"
    risk_score += 25
    print(f"WARNING : Multiple suspicious behavioral cues detected ({behavior_score}).")
elif behavior_score >= 1:
    layer_result["Layer 2"] = "WARNING"
    risk_score += 15
    print(f"WARNING : Suspicious wording/behavior detected ({behavior_score} cue(s)).")
else:
    layer_result["Layer 2"] = "PASS"
    print("PASS : No strong behavioral cues detected.")
# ============================================================
# LAYER 3: URL & ATTACHMENT INSPECTION
# ============================================================
print("\n[LAYER 3] URL & Attachment Inspection")
time.sleep(0.5)

url_score = 0
if link:
    url_lower = link.lower()
    suspicious_url_terms = [
        "bit.ly", "tinyurl", "t.co/", "goo.gl", "rb.gy", "is.gd",
        "verify", "secure", "update", "confirm", "login", "freegift",
        "password", "account", "xn--"
    ]
    if not re.match(r"^https?://", url_lower):
        url_score += 2
    if any(term in url_lower for term in suspicious_url_terms):
        url_score += 3
    if re.search(r"@|%40", url_lower):
        url_score += 3
    if url_lower.count(".") >= 4:
        url_score += 1

dangerous_extensions = (
    ".exe", ".bat", ".cmd", ".scr", ".js", ".vbs", ".msi",
    ".ps1", ".jar", ".hta", ".iso", ".lnk"
)
risky_archive_extensions = (".zip", ".rar", ".7z", ".iso")
attachment_lower = attachment.lower().strip()
if attachment_lower.endswith(dangerous_extensions):
    url_score += 5
elif attachment_lower.endswith(risky_archive_extensions):
    url_score += 2

if url_score >= 5:
    layer_result["Layer 3"] = "BLOCKED"
    risk_score += 30
    print("BLOCKED : Strongly suspicious URL or attachment indicators detected.")
elif url_score > 0:
    layer_result["Layer 3"] = "WARNING"
    risk_score += 15
    print("WARNING : Suspicious URL/attachment indicators detected.")
else:
    layer_result["Layer 3"] = "PASS"
    print("PASS : No obvious URL/attachment indicators detected.")
print("Note : This demo checks indicators only; it does not execute files or query a live threat-intelligence service.")
# ============================================================
# LAYER 4: JUST-IN-TIME USER WARNING
# ============================================================
print("\n[LAYER 4] Just-in-Time User Warning")
time.sleep(0.5)

if risk_score >= 20 or behavior_score >= 2 or url_score > 0:
    print("\nSECURITY WARNING: This message has suspicious indicators.")
    print("Do not open links, attachments, or share passwords/verification codes.")
    user_choice = input("Continue analysis anyway? (yes/no): ").strip().lower()
    if user_choice != "yes":
        layer_result["Layer 4"] = "BLOCKED"
        risk_score += 15
        user_cancelled = True
        print("BLOCKED : User chose not to continue.")
    else:
        layer_result["Layer 4"] = "WARNING ACKNOWLEDGED"
        user_cancelled = False
        print("WARNING ACKNOWLEDGED : Continuing to analysis.")
else:
    layer_result["Layer 4"] = "PASS"
    user_cancelled = False
    print("PASS : No immediate warning threshold reached.")


# ============================================================
# LAYER 5: OUT-OF-BAND VERIFICATION
# Privacy-preserving automated cross-signal check; no OTP/personal data.
# This is a local demo heuristic, not a real external verification channel.
# ============================================================
print("\n[LAYER 5] Out-of-Band Verification")
time.sleep(0.5)

verification_signals = 0
if behavior_score >= 2:
    verification_signals += 1
if url_score > 0:
    verification_signals += 1
if layer_result.get("Layer 1") in {"WARNING", "FAIL"}:
    verification_signals += 1
if amount >= 50000:
    verification_signals += 1
if any(term in combined for term in ["send code", "share the code", "otp", "password"]):
    verification_signals += 1

if verification_signals >= 3:
    layer_result["Layer 5"] = "HIGH RISK"
    risk_score += 20
    print("HIGH RISK : Multiple independent warning signals agree.")
    print("Automatic action : Recommend blocking/quarantine; no OTP or personal information requested.")
elif verification_signals >= 1:
    layer_result["Layer 5"] = "WARNING"
    risk_score += 10
    print("WARNING : Additional automated checks found suspicious signals.")
    print("No OTP or personal information requested.")
else:
    layer_result["Layer 5"] = "PASS"
    print("PASS : No additional verification signals found.")
# ============================================================
# LAYER 6: AI-BASED CONTENT ANALYSIS
# ============================================================
print("\n[LAYER 6] AI-Based Content Analysis")
time.sleep(0.5)

input_text = clean_text(sender + " " + subject + " " + message + " " + link + " " + attachment)
input_vec = vectorizer.transform([input_text])
prediction = int(model.predict(input_vec)[0])
probability = model.predict_proba(input_vec)[0]
class_to_probability = {int(cls): float(prob) for cls, prob in zip(model.classes_, probability)}
phishing_probability = class_to_probability.get(1, 0.0)
confidence = max(probability) * 100

# Strict safety override: high-risk cues can override a benign ML prediction.
strict_phishing_cues = [
    "account suspended", "account emergency", "verify your account",
    "reset your password", "share the code", "send code",
    "if it's not you", "if it is not you", "claim your prize",
    "payment failed", "confirm your identity"
]
matched_strict_cues = [cue for cue in strict_phishing_cues if cue in combined]
strict_override = (
    len(matched_strict_cues) >= 2
    or url_score >= 5
    or behavior_score >= 5
    or (phishing_probability >= 0.35 and behavior_score >= 2)
)

if prediction == 1 or strict_override:
    layer_result["Layer 6"] = "PHISHING"
    print(f"Prediction : PHISHING ({phishing_probability * 100:.2f}% model phishing probability)")
    if strict_override and prediction == 0:
        print("Strict rule override : Suspicious indicators outweighed the model's safe classification.")
    risk_score += 30
else:
    layer_result["Layer 6"] = "LEGITIMATE"
    print(f"Prediction : LEGITIMATE ({confidence:.2f}% model confidence)")
    print(f"Model phishing probability : {phishing_probability * 100:.2f}%")

# ============================================================
# FINAL DECISION & REPORT
# ============================================================
risk_score = min(100, risk_score)

if user_cancelled or risk_score >= 70:
    verdict = "BLOCKED"
elif risk_score >= 45 or layer_result.get("Layer 6") == "PHISHING":
    verdict = "QUARANTINED"
elif risk_score >= 25:
    verdict = "REVIEW REQUIRED"
else:
    verdict = "DELIVERED"

print("\n" + "=" * 70)
print("PHISHING PREVENTION SYSTEM REPORT")
print("=" * 70)
print(f"Message Type     : {MESSAGE_TYPE}")
print(f"Sender           : {sender}")
if MESSAGE_TYPE == "EMAIL":
    print(f"Subject          : {subject}")
print("-" * 70)
print("Layer Results")
for layer_name, result in layer_result.items():
    print(f"{layer_name:<34}: {result}")
print("-" * 70)
print(f"AI Prediction    : {layer_result['Layer 6']}")
print(f"AI Confidence    : {confidence:.2f}%")
print(f"Risk Score       : {risk_score}/100")
print(f"Final Decision   : {verdict}")
print("=" * 70)

print("\nSYSTEM RECOMMENDATION")
if verdict == "BLOCKED":
    print("• Do not open the message or its attachments.")
    print("• Block/report the sender through your email or messaging provider.")
elif verdict == "QUARANTINED":
    print("• Keep the message quarantined for manual review.")
    print("• Verify the sender through a known, independent channel.")
elif verdict == "REVIEW REQUIRED":
    print("• Treat the message cautiously.")
    print("• Do not click links or share passwords/verification codes.")
else:
    print("• No strong risk threshold was reached by this demo.")
    print("• Still verify unexpected requests independently.")

print("\n" + "=" * 70)
print("SYSTEM EXECUTED SUCCESSFULLY")
print("=" * 70)
print("✔ Layer 1 : Sender & Header Authentication")
print("✔ Layer 2 : Behavioral Anomaly Detection")
print("✔ Layer 3 : URL & Attachment Inspection")
print("✔ Layer 4 : Just-in-Time User Warning")
print("✔ Layer 5 : Out-of-Band Verification (automated demo checks)")
print("✔ Layer 6 : AI-Based Content Analysis")
print("\nHybrid Multi-Layer Phishing Prevention Completed Successfully.")
print("=" * 70)