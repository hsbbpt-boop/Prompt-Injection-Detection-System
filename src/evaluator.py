from collections import Counter

def evaluate(results):
    
    # results = list of dicts:
    # {
    #     "actual": 0 or 1,
    #     "predicted": "SAFE" / "SUSPICIOUS" / "ATTACK"
    # }
    

    TP = FP = TN = FN = 0

    for r in results:
        actual = r["actual"]
        pred = r["predicted"]

        # Treat SUSPICIOUS as ATTACK
        if pred == "SUSPICIOUS":
            pred = "ATTACK"

        if actual == 1 and pred == "ATTACK":
            TP += 1
        elif actual == 0 and pred == "SAFE":
            TN += 1
        elif actual == 0 and pred == "ATTACK":
            FP += 1
        elif actual == 1 and pred == "SAFE":
            FN += 1

    total = TP + TN + FP + FN

    accuracy = (TP + TN) / total if total else 0
    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0

    print("\n===== Evaluation Results =====")
    print(f"Total Samples: {total}")
    print(f"TP (Correct Attacks): {TP}")
    print(f"TN (Correct Safe): {TN}")
    print(f"FP (False Positives): {FP}")
    print(f"FN (Missed Attacks): {FN}")

    print("\n--- Metrics ---")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall (Attack Detection Rate): {recall * 100:.2f}%")

    return {
        "TP": TP,
        "TN": TN,
        "FP": FP,
        "FN": FN,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall
    }