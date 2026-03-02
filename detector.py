from gmail_reader import fetch_last_emails
from risk_engine import analyze_email
import re
import json
import datetime
import logging

# ----------------------------
# Gmail Credentials
# ----------------------------
email_user = input("Enter your Gmail: ")
email_pass = input("Enter your Gmail App Password: ")

# ----------------------------
# Logging Configuration
# ----------------------------
logging.basicConfig(
    filename="phishing_analyzer.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

print("\n=== Gmail Phishing Analyzer (SOC Mode - IMAP Mode) ===\n")

emails = fetch_last_emails(email_user, email_pass, count=5)

if not emails:
    print("No emails fetched.")
    exit()

report = []
timestamp = datetime.datetime.now().isoformat()

for i, email in enumerate(emails, start=1):
    print(f"\n========== Email {i} ==========")

    sender = email.get("sender", "")
    subject = email.get("subject", "")
    body = email.get("body", "")

    links = re.findall(r'(https?://\S+)', body)
    link = links[0] if links else ""

    result = analyze_email(sender, subject, body, link)

    print("From:", sender)
    print("Subject:", subject)
    print("Rule Score:", result["rule_score"])
    print("ML Score:", result["ml_score"])
    print("ML Probability:", result["ml_probability"], "%")
    print("Final Risk Score:", result["risk_score"])
    print("Classification:", result["classification"])

    if result["reasons"]:
        print("Reasons:")
        for reason in result["reasons"]:
            print("-", reason)
    else:
        print("No phishing indicators detected.")

    report.append({
        "timestamp": timestamp,
        "email_number": i,
        "sender": sender,
        "subject": subject,
        "rule_score": result["rule_score"],
        "ml_score": result["ml_score"],
        "ml_probability": result["ml_probability"],
        "risk_score": result["risk_score"],
        "classification": result["classification"],
        "reasons": result["reasons"]
    })

    logging.info(
        f"Analyzed Email {i} | Sender: {sender} | Final Risk: {result['risk_score']}"
    )

# ----------------------------
# Export JSON Report
# ----------------------------
with open("phishing_report.json", "w") as f:
    json.dump(report, f, indent=4)

print("\n✅ JSON security report generated: phishing_report.json")
print("✅ Log file generated: phishing_analyzer.log")