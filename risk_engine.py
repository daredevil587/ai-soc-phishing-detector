import re
from ml_engine import predict_phishing


def simple_similarity(a, b):
    matches = 0
    for x, y in zip(a, b):
        if x == y:
            matches += 1
    return matches / max(len(a), len(b))


def extract_domain_from_email(email):
    if "@" in email:
        return email.split("@")[1]
    return ""


def analyze_email(sender, subject, body, link):
    rule_score = 0
    reasons = []

    subject = subject.lower() if subject else ""
    body = body.lower() if body else ""
    sender = sender.lower() if sender else ""

    sender_domain = extract_domain_from_email(sender)

    # ============================
    # RULE-BASED DETECTION
    # ============================
    urgent_words = ["urgent", "immediately", "action required", "verify now"]
    threat_words = ["suspended", "limited", "blocked", "unauthorized"]
    money_words = ["payment", "invoice", "bank", "transfer", "refund"]

    for word in urgent_words:
        if word in subject or word in body:
            rule_score += 15
            reasons.append(f"Urgency keyword detected: {word}")

    for word in threat_words:
        if word in body:
            rule_score += 20
            reasons.append(f"Threat keyword detected: {word}")

    for word in money_words:
        if word in body:
            rule_score += 15
            reasons.append(f"Financial keyword detected: {word}")

    # ----------------------------
    # Link Analysis
    # ----------------------------
    if link:
        link = link.strip()

        if not link.startswith("https://"):
            rule_score += 20
            reasons.append("Link is not secure (HTTPS missing)")

        domain_match = re.findall(r"https?://([^/]+)", link)
        if domain_match:
            domain = domain_match[0].lower()
            domain = domain.replace("www.", "")
            base_domain = domain.split(":")[0]

            if "@" in base_domain:
                rule_score += 30
                reasons.append("Phishing URL detected using '@' trick")

            suspicious_domains = ["bit.ly", "tinyurl.com", "t.co"]
            for sd in suspicious_domains:
                if base_domain.startswith(sd):
                    rule_score += 20
                    reasons.append(f"URL shortener detected: {sd}")

            trusted_domains = [
                "paypal.com",
                "amazon.com",
                "microsoft.com",
                "google.com"
            ]

            for trusted in trusted_domains:
                similarity = simple_similarity(base_domain, trusted)
                if similarity > 0.80 and base_domain != trusted:
                    rule_score += 35
                    reasons.append(
                        f"Possible typosquatting detected (similar to {trusted})"
                    )

    # ----------------------------
    # Sender Domain Check
    # ----------------------------
    trusted_domains = [
        "paypal.com",
        "amazon.com",
        "microsoft.com",
        "google.com"
    ]

    for trusted in trusted_domains:
        similarity = simple_similarity(sender_domain, trusted)
        if similarity > 0.80 and sender_domain != trusted:
            rule_score += 30
            reasons.append(
                f"Sender domain suspicious (similar to {trusted})"
            )

    # ============================
    # 🤖 MACHINE LEARNING SECTION
    # ============================
    combined_text = subject + " " + body
    ml_probability = predict_phishing(combined_text)

    ml_score = int(ml_probability * 40)  # ML contributes max 40 points

    reasons.append(f"ML phishing probability: {round(ml_probability*100, 2)}%")

    # ============================
    # FINAL SCORE
    # ============================
    final_score = rule_score + ml_score
    final_score = min(final_score, 100)

    if final_score >= 75:
        classification = "HIGH RISK - Likely Phishing"
    elif final_score >= 40:
        classification = "SUSPICIOUS - Needs Review"
    else:
        classification = "LOW RISK - Likely Safe"

    return {
        "rule_score": rule_score,
        "ml_score": ml_score,
        "ml_probability": round(ml_probability * 100, 2),
        "risk_score": final_score,
        "classification": classification,
        "reasons": reasons
    }