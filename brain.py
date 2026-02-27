# ===============================
# IMPORTS
# ===============================

import math
from collections import Counter
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern


# ===============================
# CUSTOM REGEX RECOGNIZERS
# ===============================

aws_access_pattern = Pattern(
    name="AWS_PATTERN",
    regex=r"AKIA[0-9A-Z]{16}",
    score=0.9
)

aws_recognizer = PatternRecognizer(
    supported_entity="AWS_ACCESS_KEY",
    patterns=[aws_access_pattern]
)

aadhar_pattern = Pattern(
    name="AADHAR_PATTERN",
    regex=r"\b[0-9]\d{3}\s?\d{4}\s?\d{4}\b",
    score=0.9
)

aadhar_recognizer = PatternRecognizer(
    supported_entity="AADHAR_NUMBER",
    patterns=[aadhar_pattern]
)


# ===============================
# ENTROPY FUNCTION
# ===============================

def shannon_entropy(text):
    if not text:
        return 0

    counts = Counter(text)
    entropy = 0

    for count in counts.values():
        probability = count / len(text)
        entropy += -probability * math.log2(probability)

    return entropy


# ===============================
# MODEL CLASS
# ===============================

class Model:

    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.analyzer.registry.add_recognizer(aws_recognizer)
        self.analyzer.registry.add_recognizer(aadhar_recognizer)

    def scan(self, text):

        results = self.analyzer.analyze(
            text=text,
            entities=["AWS_ACCESS_KEY", "AADHAR_NUMBER"],
            language="en"
        )

        scored_report = []

        for res in results:
            found_text = text[res.start:res.end]
            entropy_score = shannon_entropy(found_text)

            risk = "LOW"
            if res.entity_type == "AWS_ACCESS_KEY" and entropy_score > 4.0:
                risk = "CRITICAL"
            elif res.entity_type == "AADHAR_NUMBER":
                risk = "HIGH"

            scored_report.append({
                "type": res.entity_type,
                "value": found_text,
                "entropy": round(entropy_score, 2),
                "risk": risk
            })

        return scored_report


# ===============================
# INTERACTIVE TEST
# ===============================

if __name__ == "__main__":

    model = Model()

    test = """ User1:
Name: Rahul Sharma
Phone: 9876543210
Aadhaar: 8234 5678 9012
AWS Key: AKIA1234567890ABCDEF

User2:
Name: Priya Verma
Phone: 9123456789
Aadhaar: 456712348901   # no spaces (edge case)
AWS Key: AKIA9Z8Y7X6W5V4U3T2S

User3:
Name: Arjun Mehta
Phone: 9988776655
Aadhaar: 1111 2222 3333  # random number (false positive risk)
AWS Key: AKIA1234        # broken key (too short)

User4:
Random number: 9999 8888 7777
"""

    # --------------------------------
    # CORRECT EXPECTED LABELS
    # --------------------------------
    expected_list = (
        ["AWS_ACCESS_KEY"] * 3 +
        ["AADHAR_NUMBER"] * 3
    )

    # --------------------------------
    # PREDICTIONS
    # --------------------------------
    predictions = model.scan(test)
    predicted_list = [p["type"] for p in predictions]

    # --------------------------------
    # COUNT-BASED EVALUATION
    # --------------------------------
    expected_counter = Counter(expected_list)
    predicted_counter = Counter(predicted_list)

    TP = sum((expected_counter & predicted_counter).values())
    FP = sum((predicted_counter - expected_counter).values())
    FN = sum((expected_counter - predicted_counter).values())

    precision = TP / (TP + FP + 1e-6)
    recall = TP / (TP + FN + 1e-6)
    f1 = 2 * precision * recall / (precision + recall + 1e-6)

    print("\n--- SCAN RESULTS ---")
    print(predictions)

    print("\n--- METRICS ---")
    print({
        "Precision (%)": round(precision * 100, 2),
        "Recall (%)": round(recall * 100, 2),
        "F1 Score (%)": round(f1 * 100, 2),
        "TP": TP,
        "FP": FP,
        "FN": FN
    })