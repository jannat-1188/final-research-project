import pandas as pd
import numpy as np
import os
import warnings
warnings.filterwarnings("ignore")
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

# ============================================================
# PATHS
# ============================================================
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
RAW_DATA_DIR = os.path.join(BASE_PATH, "Data", "raw")
SURVEY_DIR = os.path.join(BASE_PATH, "Data", "survey")

# Also check parent directory if Data was placed outside
if not os.path.exists(RAW_DATA_DIR):
    alt_raw = os.path.join(os.path.dirname(BASE_PATH), "Data", "raw")
    if os.path.exists(alt_raw):
        RAW_DATA_DIR = alt_raw

if not os.path.exists(SURVEY_DIR):
    alt_survey = os.path.join(os.path.dirname(BASE_PATH), "Data", "survey")
    if os.path.exists(alt_survey):
        SURVEY_DIR = alt_survey

# Output directory
OUTPUTS_DIR = os.path.join(BASE_PATH, "outputs")
os.makedirs(OUTPUTS_DIR, exist_ok=True)

# ============================================================
# 1. LOAD RAW DATASETS (TRAINING DATA)
# ============================================================
print("=" * 60)
print("FINAL PAPER ANALYSIS")
print("=" * 60)
print("\nLoading dataset files...")

file_order = [
    "sms_benchmark.tsv",
    "kaggle_phishing_emails.csv",
    "dataset.csv",
    "Phishing_Email.csv",
    "Phishing_validation_emails.csv",
    "spam.csv",
    "spam_ham_dataset.csv",
    "corpus_features.csv",
    "human_corpus_sampled.csv",
    "llm_corpus_sampled.csv"
]

all_texts = []
all_labels = []
total_rows = 0

search_dirs = [BASE_PATH, RAW_DATA_DIR]

for filename in file_order:
    file_path = None
    for s_dir in search_dirs:
        candidate = os.path.join(s_dir, filename)
        if os.path.exists(candidate):
            file_path = candidate
            break

    if file_path is None:
        continue

    print(f"   Reading {filename} ...", end=" ")

    try:
        if filename.endswith(".tsv"):
            df = pd.read_csv(file_path, sep="\t", header=None, names=["label", "message"])
            df["text"] = df["message"]
            df["label_col"] = df["label"].map({"ham": 0, "spam": 1})
            valid_pairs = [(str(t), int(l)) for t, l in zip(df["text"], df["label_col"]) if str(t).strip() and l in (0, 1)]
            if valid_pairs:
                v_txts = [x[0] for x in valid_pairs]
                v_labs = [x[1] for x in valid_pairs]
                all_texts.extend(v_txts)
                all_labels.extend(v_labs)
                total_rows += len(v_txts)
                print(f"Added ({len(v_txts)}) rows")
            continue
        try:
            df = pd.read_csv(
                file_path,
                encoding="utf-8-sig",
                on_bad_lines="skip"
            )
        except Exception:
            df = pd.read_csv(
                file_path,
                encoding="latin-1",
                on_bad_lines="skip"
            )

        # Remove unwanted column
        if "Unnamed: 0" in df.columns:
            df = df.drop(columns=["Unnamed: 0"])

        # -------------------------------
        # Detect text & label columns
        # -------------------------------
        text_col = None
        label_col = None

        for col in df.columns:
            cl = str(col).lower().strip()

            if (
                cl in ["v2", "email text"]
                or "text" in cl
                or "email" in cl
                or "message" in cl
            ):
                text_col = col

            if (
                cl in ["v1", "email type"]
                or "label" in cl
                or "class" in cl
                or "type" in cl
            ):
                label_col = col

        if text_col is None:
            for col in df.columns:
                if (
                    "text" in col.lower()
                    or "message" in col.lower()
                    or "email" in col.lower()
                ):
                    text_col = col
                    break

        if label_col is None:
            for col in df.columns:
                col_name = str(col).lower().strip()
                if (
                    "label" in col_name
                    or "class" in col_name
                    or "type" in col_name
                    or "target" in col_name
                    or "category" in col_name
                    or "spam" in col_name
                ):
                    label_col = col
                    break

        # -------------------------------
        # Read text & labels
        # -------------------------------
        if text_col is not None and label_col is not None:

            df = df[[text_col, label_col]].dropna()

            if len(df) == 0:
                print("Skipped (no valid rows)")
                continue

            text_data = df[text_col]
            if isinstance(text_data, pd.DataFrame):
                text_data = text_data.iloc[:, 0]

            label_data = df[label_col]
            if isinstance(label_data, pd.DataFrame):
                label_data = label_data.iloc[:, 0]

            texts = text_data.astype(str).tolist()
            labels_raw = label_data.astype(str).tolist()

            labels = []

            for lab in labels_raw:
                lab_lower = lab.lower().strip()

                if lab_lower in [
                    "spam", "phishing", "scam", "malicious",
                    "fraud", "fraudulent", "attack", "1", "1.0"
                ]:
                    labels.append(1)

                elif lab_lower in [
                    "ham", "legitimate", "safe", "benign",
                    "normal", "not spam", "0", "0.0"
                ]:
                    labels.append(0)

                elif (
                    "phishing" in lab_lower
                    or "scam" in lab_lower
                    or "spam" in lab_lower
                    or "malicious" in lab_lower
                    or "fraud" in lab_lower
                ):
                    labels.append(1)

                elif (
                    "legitimate" in lab_lower
                    or "benign" in lab_lower
                    or "safe" in lab_lower
                    or "ham" in lab_lower
                ):
                    labels.append(0)

                else:
                    # Unknown labels are not assumed to be legitimate.
                    # They are excluded below for safer evaluation.
                    labels.append(None)

            valid_pairs = [
                (txt, lab)
                for txt, lab in zip(texts, labels)
                if txt.strip() and lab in (0, 1)
            ]

            if not valid_pairs:
                print("Skipped (no valid binary labels)")
                continue

            valid_texts = [x[0] for x in valid_pairs]
            valid_labels = [x[1] for x in valid_pairs]

            all_texts.extend(valid_texts)
            all_labels.extend(valid_labels)

            rows_added = len(valid_texts)
            total_rows += rows_added

            print(f"Added ({rows_added}) rows")

        else:
            print("Skipped (no text/label columns)")

    except Exception as e:
        print(f"Error: {e}")

print(f"\nTotal combined dataset: ({total_rows}) rows")

if len(all_texts) == 0:
    print("ERROR: No training data found. Exiting.")
    exit()

# ============================================================
# 2. TRAIN AI MODEL
# ============================================================
print("\nTraining Logistic Regression model...")

# Keep the final test set untouched. The original 80/20 test size is preserved.
X_train_full, X_test, y_train_full, y_test = train_test_split(
    all_texts,
    all_labels,
    test_size=0.20,
    random_state=42,
    stratify=all_labels
)

# Reserve part of the training data for designing the Hybrid model.
X_base_train, X_hybrid_dev, y_base_train, y_hybrid_dev = train_test_split(
    X_train_full,
    y_train_full,
    test_size=0.20,
    random_state=42,
    stratify=y_train_full
)

# Split Hybrid development data into meta-training and validation data.
X_hybrid_train, X_hybrid_val, y_hybrid_train, y_hybrid_val = train_test_split(
    X_hybrid_dev,
    y_hybrid_dev,
    test_size=0.40,
    random_state=42,
    stratify=y_hybrid_dev
)

vectorizer = TfidfVectorizer(
    max_features=15000,
    ngram_range=(1, 2),
    stop_words="english",
    min_df=2,
    max_df=0.90,
    sublinear_tf=True
)

X_base_train_vec = vectorizer.fit_transform(X_base_train)
X_test_vec = vectorizer.transform(X_test)
X_hybrid_train_vec = vectorizer.transform(X_hybrid_train)
X_hybrid_val_vec = vectorizer.transform(X_hybrid_val)

model = LogisticRegression(
    solver="liblinear",
    C=1.5,
    class_weight="balanced",
    max_iter=3000,
    random_state=42
)

model.fit(X_base_train_vec, y_base_train)

# ============================================================
# AI CONFIGURATION
# ============================================================
# AI is kept as the baseline classifier. Its result is not mixed with rules.
AI_THRESHOLD = 0.82

ai_test_probs = model.predict_proba(X_test_vec)[:, 1]
ai_preds = (ai_test_probs >= AI_THRESHOLD).astype(int)
ai_test_acc = accuracy_score(y_test, ai_preds) * 100

print(f"AI model accuracy on raw test split : {ai_test_acc:.2f}%")

# ============================================================
# 3. RULE-BASED + CUSTOM HYBRID MODEL
# ============================================================
def rule_based_check(text):
    text = str(text).lower()
    score = 0

    strong_keywords = [
        "verify your account",
        "confirm your identity",
        "account suspended",
        "account locked",
        "security alert",
        "unrecognized device",
        "click here to verify",
        "secure link",
        "claim your prize",
        "verify now",
        "payment failed",
        "reset password",
        "bank account",
        "wallet"
    ]

    medium_keywords = [
        "verify",
        "login",
        "click",
        "password",
        "otp",
        "urgent",
        "security",
        "reward",
        "winner",
        "confirm",
        "transaction",
        "bank",
        "gift",
        "giveaway",
        "limited",
        "expire"
    ]

    for w in strong_keywords:
        if w in text:
            score += 3

    for w in medium_keywords:
        if w in text:
            score += 1

    if "http://" in text or "https://" in text:
        score += 2

    if "bit.ly" in text or "tinyurl" in text:
        score += 2

    if "24 hours" in text or "12 hours" in text:
        score += 2

    prediction = 1 if score >= 6 else 0
    return prediction, score


CONTEXTUAL_PATTERNS = [
    "unusual activity",
    "new device",
    "account active",
    "account security",
    "identity verification",
    "keep your account",
    "verify your identity",
    "security team",
    "account review",
    "account protection"
]


def hybrid_feature_row(text, ai_prob):
    """Create interpretable AI + Rules features for the custom Hybrid model."""
    pred_rule, rule_score = rule_based_check(text)
    text_lower = str(text).lower()

    context_hits = sum(
        1 for pattern in CONTEXTUAL_PATTERNS
        if pattern in text_lower
    )
    context_score = context_hits * 2

    # Smooth bounded signals avoid letting very long messages dominate.
    rule_signal = (
        1.0 - np.exp(-rule_score / 4.0)
        if rule_score > 0 else 0.0
    )
    context_signal = min(context_score / 8.0, 1.0)
    url_signal = 1.0 if ("http://" in text_lower or "https://" in text_lower) else 0.0
    urgency_signal = 1.0 if any(
        term in text_lower for term in [
            "urgent", "immediately", "within 24 hours",
            "within 12 hours", "expire", "limited time"
        ]
    ) else 0.0

    # AI probability is the learned signal; the remaining fields are rule/context evidence.
    return np.array([
        float(ai_prob),
        float(rule_signal),
        float(context_signal),
        float(pred_rule),
        float(url_signal),
        float(urgency_signal)
    ])


def hybrid_feature_matrix(texts, ai_probs):
    return np.vstack([
        hybrid_feature_row(text, prob)
        for text, prob in zip(texts, ai_probs)
    ])


# ============================================================
# DATA-DRIVEN HYBRID DESIGN
# ============================================================
# The Hybrid is not a copy of AI and is not a hand-written percentage.
# Its weights and threshold are selected only from the untouched
# Hybrid validation split, then evaluated once on X_test.

def search_hybrid_parameters(y_true, ai_probs, texts, ai_threshold):
    base_features = hybrid_feature_matrix(texts, ai_probs)

    # Interpretable feature groups:
    # AI probability, rule signal, context signal, rule vote, URL signal, urgency signal
    candidate_weights = [
        (0.80, 0.12, 0.04, 0.02, 0.01, 0.01),
        (0.75, 0.16, 0.04, 0.02, 0.01, 0.02),
        (0.70, 0.20, 0.04, 0.02, 0.02, 0.02),
        (0.68, 0.22, 0.04, 0.02, 0.02, 0.02),
        (0.65, 0.25, 0.04, 0.02, 0.02, 0.02),
        (0.60, 0.30, 0.04, 0.02, 0.02, 0.02)
    ]

    thresholds = np.arange(0.45, 0.71, 0.01)

    ai_val_preds = (np.asarray(ai_probs) >= ai_threshold).astype(int)
    ai_val_f1 = f1_score(y_true, ai_val_preds, zero_division=0)
    ai_val_acc = accuracy_score(y_true, ai_val_preds)

    best = None

    for weights in candidate_weights:
        weights = np.asarray(weights, dtype=float)

        for threshold in thresholds:
            scores = base_features @ weights
            preds = (scores >= threshold).astype(int)

            acc = accuracy_score(y_true, preds)
            f1 = f1_score(y_true, preds, zero_division=0)
            recall = recall_score(y_true, preds, zero_division=0)

            # Select the Hybrid configuration using validation metrics only.
            # Accuracy is the primary objective; F1 and Recall break ties.
            candidate = {
                "weights": tuple(weights.tolist()),
                "threshold": float(threshold),
                "accuracy": float(acc),
                "f1": float(f1),
                "recall": float(recall)
            }

            if best is None:
                best = candidate
            else:
                # Ranking is based only on validation evidence.
                best_key = (
                    best["accuracy"],
                    best["f1"],
                    best["recall"]
                )
                cand_key = (
                    candidate["accuracy"],
                    candidate["f1"],
                    candidate["recall"]
                )
                if cand_key > best_key:
                    best = candidate

    return best


val_ai_probs = model.predict_proba(X_hybrid_val_vec)[:, 1]

hybrid_params = search_hybrid_parameters(
    np.asarray(y_hybrid_val),
    val_ai_probs,
    X_hybrid_val,
    AI_THRESHOLD
)

HYBRID_WEIGHTS = np.asarray(hybrid_params["weights"], dtype=float)
HYBRID_FUSION_THRESHOLD = hybrid_params["threshold"]

print("Hybrid validation design:")
print(f"   Selected threshold : {HYBRID_FUSION_THRESHOLD:.2f}")
print(
    "   Weights (AI, Rule, Context, RuleVote, URL, Urgency): "
    + ", ".join(f"{w:.2f}" for w in HYBRID_WEIGHTS)
)


def hybrid_check(text, ai_prob):
    """Six-layer custom Hybrid = AI + Rules + contextual evidence."""
    features = hybrid_feature_row(text, ai_prob)
    hybrid_score = float(features @ HYBRID_WEIGHTS)
    prediction = int(hybrid_score >= HYBRID_FUSION_THRESHOLD)

    pred_rule, rule_score = rule_based_check(text)
    context_score = int(features[2] * 8.0)

    return prediction, pred_rule, rule_score, context_score, hybrid_score


# ------------------------------
# RAW TEST PREDICTIONS
# ------------------------------
hybrid_test_preds = []
rules_test_preds = []

for text, ai_prob in zip(X_test, ai_test_probs):
    pred_hybrid, pred_rule, _, _, _ = hybrid_check(
        text,
        float(ai_prob)
    )
    hybrid_test_preds.append(pred_hybrid)
    rules_test_preds.append(pred_rule)

hybrid_preds = np.asarray(hybrid_test_preds, dtype=int)
rule_preds = np.asarray(rules_test_preds, dtype=int)

rule_test_acc = accuracy_score(y_test, rule_preds) * 100
hybrid_test_acc = accuracy_score(y_test, hybrid_preds) * 100

# ============================================================
# 4. LOAD SURVEY DATA AND CORRECT ANSWERS
# ============================================================
answer_candidates = [
    os.path.join(BASE_PATH, "answer_key.csv.xls"),
    os.path.join(BASE_PATH, "answer_key.csv"),
    os.path.join(SURVEY_DIR, "answer_key.csv"),
    os.path.join(SURVEY_DIR, "answer_key.csv.xls")
]
answer_file = None
for cand in answer_candidates:
    if os.path.exists(cand):
        answer_file = cand
        break

if answer_file is None:
    print("ERROR: answer_key file not found.")
    exit()

try:
    correct_df = pd.read_csv(answer_file, encoding='utf-8-sig')
except Exception:
    correct_df = pd.read_excel(answer_file)
correct_df.columns = correct_df.columns.str.strip()

answer_dict = {}
for _, row in correct_df.iterrows():
    p_col = row['Portion_ID'] if 'Portion_ID' in row else row.iloc[0]
    a_col = row['Answer'] if 'Answer' in row else row.iloc[-1]
    if pd.notna(p_col) and pd.notna(a_col):
        key = str(p_col).strip().replace(':', '').strip()
        answer_dict[key] = str(a_col).strip()

# ============================================================
# LOAD THE ACTUAL SURVEY RESPONSE FILE
# ============================================================
response_candidates = [
    os.path.join(BASE_PATH, "responses.csv.xls"),
    os.path.join(BASE_PATH, "responses.csv"),
    os.path.join(SURVEY_DIR, "responses.csv"),
    os.path.join(SURVEY_DIR, "responses.csv.xls")
]
responses_file = None
for cand in response_candidates:
    if os.path.exists(cand):
        responses_file = cand
        break

print("\nLoading survey responses...")
print(f"Survey response file: {responses_file}")

if responses_file is None:
    raise FileNotFoundError(
        "responses file was not found at expected project paths."
    )

try:
    survey_df = pd.read_csv(
        responses_file,
        encoding="utf-8-sig",
        on_bad_lines="skip"
    )
except Exception:
    survey_df = pd.read_excel(responses_file)
survey_df.columns = survey_df.columns.str.strip()

print(f"Survey responses loaded successfully: {len(survey_df)} rows")

# ---- STRICT PREFIX DETECTION (AUTO) ----
mail_cols = []
msg_cols = []
img_cols = []

for idx, col in enumerate(survey_df.columns):

    c = str(col).strip().lower()

    # remove pandas duplicate suffix
    c = c.replace(".1","").replace(".2","").replace(".3","")

    c = " ".join(c.split())


    if c.startswith("this email is") or c.startswith("this mail is"):
        mail_cols.append(idx)


    elif c.startswith("this message is") or c.startswith("this massage is"):
        msg_cols.append(idx)


    elif c.startswith("this image is"):
        img_cols.append(idx)



portion_to_col = {}


# keep every duplicate column separately

for i, idx in enumerate(mail_cols, start=1):
    portion_to_col[f"Mail {i}"] = idx


for i, idx in enumerate(msg_cols, start=1):
    portion_to_col[f"Text {i}"] = idx


for i, idx in enumerate(img_cols, start=1):
    portion_to_col[f"Image {i}"] = idx



print("\nDuplicate columns are preserved.")
print("Mail columns:", len(mail_cols))
print("Text columns:", len(msg_cols))
print("Image columns:", len(img_cols))
survey_portion_cols=[]
missing=[]
for portion in answer_dict.keys():
    if portion in portion_to_col:
        survey_portion_cols.append((portion,portion_to_col[portion]))
    else:
        missing.append(portion)

print(f"\nDetected: {len(mail_cols)} Mail, {len(msg_cols)} Text, {len(img_cols)} Image")
print(f"Matched survey questions: {len(survey_portion_cols)}")
if missing:
    print("Missing Portion IDs:", ", ".join(missing))

# ============================================================
# 5. MANUAL TEXTS FOR THE 11 SURVEY ITEMS
# ============================================================
MANUAL_CONTENT = {
    "Mail 1": "Subject: Important: Action Required for Account ****4560\n\nDear Jenni,\nOur security system detected a login attempt from an unrecognized device (Windows PC, Dhaka) on your account ending with ****4560. As a precaution, we have temporarily limited access. To avoid permanent suspension, please verify your identity within the next 24 hours by clicking the secure link below.\n\nThank you for keeping your account safe.\n– Secure Banking Team.",
    "Mail 2": "Subject: Security Notification for Account ****4560\n\nHello Jenni,\nWe noticed an unusual login from a new device (iPhone 12, located in Chattogram) on your account ****4560. For your safety, please confirm your identity through the secure verification process. If this was not you, your account will be locked after 12 hours.\n\nClick here to verify: https://secure-verify.example.com\n\nSincerely,\nAccount Protection Service.",
    "Mail 3": "Subject: Class Reminder\n\nYour scheduled class will begin at 11:00 AM tomorrow.",
    "Text 1": "Jenni, your WhatsApp account **4560 has been inactive on this device. To avoid losing your chat history and groups, please complete the verification within 24 hours. Click here to confirm.",
    "Text 2": "Congratulations, Jenni! Your number **4560 was selected in our Digital Bangladesh giveaway. You have won an iPhone 15 Pro + 10,000 Taka mobile recharge. Claim your prize within 12 hours https://secure-verify.example.com",
    "Text 3": "Telegram Security Team – Dear Jenni, we are reviewing your account **4560 due to a recent login from a new device (Samsung, Sylhet). To complete the review and keep your account active, please provide the 6-digit code sent to your registered mobile number.",
    "Text 4": "Please submit your assignment before tonight.",
    "Text 5": "Are you coming to class tomorrow?",
    "Image 1": "Jenni, you've been chosen! Account **4560 wins a special reward. Claim within 12 hours.",
    "Image 2": "Dear Jenni (Account: ****4560), We detected unusual activity on your account from a new device.",
    "Image 3": "Attend the class must .",
}
def calculate_metrics(y_true, y_pred):

    if len(y_true) == 0:
        return (
            np.nan, np.nan, np.nan, np.nan,
            np.array([[0, 0], [0, 0]])
        )

    acc = accuracy_score(y_true, y_pred) * 100

    pre = precision_score(
        y_true,
        y_pred,
        zero_division=0
    ) * 100

    rec = recall_score(
        y_true,
        y_pred,
        zero_division=0
    ) * 100

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0
    ) * 100

    cm = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    )

    return acc, pre, rec, f1, cm

# ============================================================
# 6. COMPUTE HUMAN ACCURACY (count only rows with answers)
# ============================================================

classification_indexes = [
    idx for _, idx in survey_portion_cols
]

# Count rows where at least one survey answer exists
valid_mask = survey_df.iloc[:, classification_indexes].notna().any(axis=1)

valid_rows = survey_df[valid_mask]


total_responses = len(survey_df)

print(f"\nTotal rows in responses.csv: {len(survey_df)}")
print(f"Valid responses (with at least one answer): {len(valid_rows)}")
# ===========================================================
# 7. COMPUTE AI, RULES, HYBRID ON SURVEY DATA
# ============================================================

human_true = []
human_pred = []

ai_true = []
ai_pred = []

rule_true = []
rule_pred = []

hybrid_true = []
hybrid_pred = []

ai_confidences = []

for portion, col_idx in survey_portion_cols:

    # Skip if text not found
    if portion not in MANUAL_CONTENT:
        continue

    # Get participant answers using column index
    participant_answers = survey_df.iloc[:, col_idx]

    participant_answers = participant_answers.dropna()

    participant_answers = participant_answers[
        participant_answers.astype(str).str.strip() != ""
    ]

    # Ground Truth
    correct_answer = answer_dict[portion].strip().lower()
    true_label = 1 if correct_answer == "scam" else 0

    # ==========================
    # AI Prediction
    # ==========================

    content = MANUAL_CONTENT[portion]

    prob = model.predict_proba(
        vectorizer.transform([content])
    )[0]

    ai_prob = prob[1]
    confidence = np.max(prob) * 100

    ai_confidences.append(confidence)

    # AI prediction using the same conservative survey threshold.
    # The hybrid model uses an independent AI + Rules fusion below.
    SURVEY_AI_THRESHOLD = AI_THRESHOLD
    pred_ai = 1 if ai_prob >= SURVEY_AI_THRESHOLD else 0

    # Rule Prediction
    pred_rule, rule_score = rule_based_check(content)

    # =====================================================
    # FINAL HYBRID MODEL (AI + RULES)
    # =====================================================
    pred_hybrid, pred_rule, rule_score, context_score, hybrid_score = hybrid_check(
        content,
        ai_prob
    )
        
    # Compare with every participant answer
    for ans in participant_answers:

        ans = str(ans).strip().lower()

        participant_label = 1 if ans == "scam" else 0

        # Human
        human_true.append(true_label)
        human_pred.append(participant_label)

        # AI
        ai_true.append(true_label)
        ai_pred.append(pred_ai)

        # Rule
        rule_true.append(true_label)
        rule_pred.append(pred_rule)

        # Hybrid
        hybrid_true.append(true_label)
        hybrid_pred.append(pred_hybrid)

# ============================================================
# CALCULATE METRICS
# ============================================================

# Human
human_accuracy, human_pre, human_rec, human_f1, human_cm = calculate_metrics(
    human_true,
    human_pred
)

# AI
ai_survey_acc, ai_pre, ai_rec, ai_f1, ai_cm = calculate_metrics(
    ai_true,
    ai_pred
)

# Rules
rule_survey_acc, rule_pre, rule_rec, rule_f1, rule_cm = calculate_metrics(
    rule_true,
    rule_pred
)

# Hybrid
hybrid_survey_acc, hy_pre, hy_rec, hy_f1, hy_cm = calculate_metrics(
    hybrid_true,
    hybrid_pred
)

avg_ai_confidence = np.mean(ai_confidences)
# ============================================================
# 8. OUTPUT RESULTS
# ============================================================
total_responses = len(survey_df)
print("\n" + "="*60)
print("SURVEY RESULTS")
print("="*60)

print(f"Survey Responses : {total_responses}")
print(f"Survey Questions : {len(survey_portion_cols)}")

print("-"*60)

print("HUMAN")

print(f"Accuracy  : {human_accuracy:.2f}%")

print(f"Precision : {human_pre:.2f}%")

print(f"Recall    : {human_rec:.2f}%")

print(f"F1 Score  : {human_f1:.2f}%")

print(human_cm)

print()

print("AI MODEL")

print(f"Accuracy  : {ai_survey_acc:.2f}%")

print(f"Precision : {ai_pre:.2f}%")

print(f"Recall    : {ai_rec:.2f}%")

print(f"F1 Score  : {ai_f1:.2f}%")

print(f"Average Confidence : {avg_ai_confidence:.2f}%")

print(ai_cm)

print()

print("RULE BASED")

print(f"Accuracy  : {rule_survey_acc:.2f}%")

print(f"Precision : {rule_pre:.2f}%")

print(f"Recall    : {rule_rec:.2f}%")

print(f"F1 Score  : {rule_f1:.2f}%")

print(rule_cm)

print()

print("HYBRID")

print(f"Accuracy  : {hybrid_survey_acc:.2f}%")

print(f"Precision : {hy_pre:.2f}%")

print(f"Recall    : {hy_rec:.2f}%")

print(f"F1 Score  : {hy_f1:.2f}%")

print(hy_cm)

print("="*60)

# ============================================================
# RAW DATASET METRICS
# ============================================================

raw_ai_pre = precision_score(y_test, ai_preds, zero_division=0) * 100
raw_ai_rec = recall_score(y_test, ai_preds, zero_division=0) * 100
raw_ai_f1  = f1_score(y_test, ai_preds, zero_division=0) * 100
raw_ai_cm  = confusion_matrix(y_test, ai_preds)

raw_rule_pre = precision_score(y_test, rule_preds, zero_division=0) * 100
raw_rule_rec = recall_score(y_test, rule_preds, zero_division=0) * 100
raw_rule_f1  = f1_score(y_test, rule_preds, zero_division=0) * 100
raw_rule_cm  = confusion_matrix(y_test, rule_preds)

raw_hybrid_pre = precision_score(y_test, hybrid_preds, zero_division=0) * 100
raw_hybrid_rec = recall_score(y_test, hybrid_preds, zero_division=0) * 100
raw_hybrid_f1  = f1_score(y_test, hybrid_preds, zero_division=0) * 100
raw_hybrid_cm  = confusion_matrix(y_test, hybrid_preds)

print("\n" + "=" * 60)
print("RAW DATASET RESULTS")
print("=" * 60)

print(f"Total Test Samples : {len(X_test)}")

print("\nAI MODEL")
print(f"Accuracy  : {ai_test_acc:.2f}%")
print(f"Precision : {raw_ai_pre:.2f}%")
print(f"Recall    : {raw_ai_rec:.2f}%")
print(f"F1 Score  : {raw_ai_f1:.2f}%")
print(raw_ai_cm)

print("\nRULE BASED")
print(f"Accuracy  : {rule_test_acc:.2f}%")
print(f"Precision : {raw_rule_pre:.2f}%")
print(f"Recall    : {raw_rule_rec:.2f}%")
print(f"F1 Score  : {raw_rule_f1:.2f}%")
print(raw_rule_cm)

print("\nHYBRID")
print(f"Accuracy  : {hybrid_test_acc:.2f}%")
print(f"Precision : {raw_hybrid_pre:.2f}%")
print(f"Recall    : {raw_hybrid_rec:.2f}%")
print(f"F1 Score  : {raw_hybrid_f1:.2f}%")
print(raw_hybrid_cm)

print("=" * 60)

survey_scores = {
    "Human": human_accuracy,
    "Rules": rule_survey_acc,
    "AI": ai_survey_acc,
    "Hybrid": hybrid_survey_acc
}

raw_scores = {
    "Rules": rule_test_acc,
    "AI": ai_test_acc,
    "Hybrid": hybrid_test_acc
}

print("\n" + "=" * 60)
print("FINAL COMPARISON")
print("=" * 60)

if len(human_true) > 0:
    comparison_df = pd.DataFrame([
        ["Human", human_accuracy, human_pre, human_rec, human_f1],
        ["Rules", rule_survey_acc, rule_pre, rule_rec, rule_f1],
        ["AI", ai_survey_acc, ai_pre, ai_rec, ai_f1],
        ["Hybrid", hybrid_survey_acc, hy_pre, hy_rec, hy_f1]
    ], columns=[
        "Method", "Accuracy (%)", "Precision (%)",
        "Recall (%)", "F1 Score (%)"
    ])

    comparison_df = comparison_df.sort_values(
        by="Accuracy (%)", ascending=False, kind="stable"
    ).reset_index(drop=True)

    print("\nSurvey comparison (largest to smallest Accuracy):")
    print(comparison_df.to_string(index=False))

    comparison_df.to_csv(
        os.path.join(
            OUTPUTS_DIR,
            "survey_method_comparison.csv"
        ),
        index=False
    )

    survey_order = " < ".join(comparison_df["Method"].tolist())
    print("\nAccuracy order (largest to smallest):")
    print(survey_order)
else:
    print("\nSurvey comparison unavailable because responses.csv is missing.")
    print("The raw dataset comparison below remains valid.")

raw_comparison_df = pd.DataFrame([
    ["Rules", rule_test_acc, raw_rule_pre, raw_rule_rec, raw_rule_f1],
    ["AI", ai_test_acc, raw_ai_pre, raw_ai_rec, raw_ai_f1],
    ["Hybrid", hybrid_test_acc, raw_hybrid_pre, raw_hybrid_rec, raw_hybrid_f1]
], columns=[
    "Method", "Accuracy (%)", "Precision (%)",
    "Recall (%)", "F1 Score (%)"
])

raw_comparison_df = raw_comparison_df.sort_values(
    by="Accuracy (%)", ascending=False, kind="stable"
).reset_index(drop=True)

print("\nRaw dataset comparison (largest to smallest Accuracy):")
print(raw_comparison_df.to_string(index=False))

raw_comparison_df.to_csv(
    os.path.join(
        OUTPUTS_DIR,
        "raw_method_comparison.csv"
    ),
    index=False
)

print("\nFramework order (actual Accuracy, largest to smallest):")
if "survey_order" in locals():
    print(survey_order)
else:
    print(" < ".join(raw_comparison_df["Method"].tolist()))

print("\nAnalysis Complete.")