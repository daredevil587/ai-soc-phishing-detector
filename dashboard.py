import streamlit as st
import json
import pandas as pd
import plotly.graph_objects as go
import matplotlib.pyplot as plt
from ml_engine import get_model_accuracy
from risk_engine import analyze_email

st.set_page_config(page_title="SOC Phishing Dashboard", layout="wide")

st.title("🛡 AI-Powered SOC Phishing Detection Dashboard")

# =========================================================
# ✍️ MANUAL EMAIL ANALYZER (RECRUITER DEMO MODE)
# =========================================================

st.markdown("---")
st.header("✍️ Manual Email Analyzer (Demo Mode)")

demo_sender = st.text_input("Sender Email", placeholder="example@domain.com")
demo_subject = st.text_input("Email Subject", placeholder="Urgent: Verify your account")
demo_body = st.text_area("Email Body", height=150, placeholder="Paste email content here...")
demo_link = st.text_input("Optional Link (if email contains URL)")

if st.button("🔍 Analyze This Email"):

    if demo_subject or demo_body:
        result = analyze_email(demo_sender, demo_subject, demo_body, demo_link)

        st.subheader("🔎 Analysis Result")

        col1, col2, col3 = st.columns(3)

        col1.metric("Rule Score", result["rule_score"])
        col2.metric("ML Score", result["ml_score"])
        col3.metric("ML Probability", f"{result['ml_probability']}%")

        fig_demo = go.Figure(go.Indicator(
            mode="gauge+number",
            value=result["risk_score"],
            number={'suffix': "/100"},
            title={'text': "Final Risk Score"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "red" if result["risk_score"] >= 70 else "orange"},
                'steps': [
                    {'range': [0, 35], 'color': "#00ff00"},
                    {'range': [35, 70], 'color': "#ffaa00"},
                    {'range': [70, 100], 'color': "#ff0000"}
                ],
            }
        ))

        fig_demo.update_layout(height=300)
        st.plotly_chart(fig_demo, width="stretch")

        st.success(f"Classification: {result['classification']}")

        if result["reasons"]:
            st.write("**Reasons Detected:**")
            for reason in result["reasons"]:
                st.write("-", reason)
    else:
        st.warning("Please enter subject or body to analyze.")

st.markdown("---")

# =========================================================
# 📬 GMAIL DASHBOARD SECTION (PUBLIC SAFE MODE)
# =========================================================

st.info("📌 Gmail scanning disabled in public demo version.")

try:
    with open("phishing_report.json", "r") as f:
        data = json.load(f)

    df = pd.DataFrame(data)

    if df.empty:
        st.warning("No emails analyzed yet.")
        st.stop()

    # 🚨 Alert Banner
    if any(df["classification"] == "HIGH RISK - Likely Phishing"):
        st.error("🚨 HIGH RISK PHISHING EMAIL DETECTED")

    # 🤖 ML Accuracy
    accuracy = get_model_accuracy()
    if accuracy:
        st.metric("🤖 ML Model Accuracy", f"{round(accuracy*100,2)}%")

    # 🎯 ML Probability Gauge
    max_prob = df["ml_probability"].max()

    fig_prob = go.Figure(go.Indicator(
        mode="gauge+number",
        value=max_prob,
        number={'suffix': "%"},
        title={'text': "Highest ML Phishing Probability"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "red" if max_prob >= 70 else "orange"},
            'steps': [
                {'range': [0, 40], 'color': "#00ff00"},
                {'range': [40, 70], 'color': "#ffaa00"},
                {'range': [70, 100], 'color': "#ff0000"}
            ],
        }
    ))

    fig_prob.update_layout(height=300)
    st.plotly_chart(fig_prob, width="stretch")

    # ⚖ Rule vs ML Comparison
    st.subheader("⚖ Rule Score vs ML Score Comparison")

    comparison_df = df[["subject", "rule_score", "ml_score"]]
    st.bar_chart(comparison_df.set_index("subject"))

    # 📊 Detection Table
    st.subheader("📊 Detection Breakdown")

    st.dataframe(df[
        [
            "sender",
            "rule_score",
            "ml_score",
            "ml_probability",
            "risk_score",
            "classification"
        ]
    ])

    # 📈 Risk Distribution
    st.subheader("📈 Risk Category Distribution")

    fig2, ax = plt.subplots()
    df["classification"].value_counts().plot.pie(autopct="%1.1f%%", ax=ax)
    ax.set_ylabel("")
    st.pyplot(fig2)

    # ⬇ CSV Download
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇ Download Full Report (CSV)",
        csv,
        "phishing_report.csv",
        "text/csv"
    )

except FileNotFoundError:
    st.warning("No phishing_report.json found. Run detector locally to generate sample data.")