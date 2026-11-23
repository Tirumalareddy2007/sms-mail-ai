import os
import json
from typing import List, Literal
import pandas as pd
import streamlit as st
from pydantic import BaseModel, Field
from groq import Groq

st.set_page_config(page_title="Cloud AI Phishing & Inbox Sorter", page_icon="🛡️", layout="wide")

class SingleAnalysisResult(BaseModel):
    category: Literal["Safe / Legitimate", "Promotional / Spam", "Suspicious", "High-Risk Phishing"]
    risk_score: int = Field(description="0 to 100")
    red_flags: List[str]
    explanation: str
    recommended_action: str

class BatchItemResult(BaseModel):
    id: int
    sender_or_preview: str
    folder: Literal["Primary (Safe)", "Promotions / Spam", "Quarantine (Phishing)"]
    risk_score: int
    reason: str

class BatchSortResult(BaseModel):
    sorted_messages: List[BatchItemResult]

def extract_json(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text

with st.sidebar:
    st.header("☁️ Cloud AI Configuration")
    st.caption("Powered by Groq Cloud LLM API")
    api_key = st.text_input("Enter Groq API Key", type="password", value=os.environ.get("GROQ_API_KEY", ""))

    available_models = ["Enter API key above to load models"]
    if api_key:
        try:
            temp_client = Groq(api_key=api_key)
            models_resp = temp_client.models.list()
            excluded = ("whisper", "guard", "tts", "orpheus", "playai", "distil-whisper")
            fetched = [m.id for m in models_resp.data if not any(w in m.id.lower() for w in excluded)]
            if fetched:
                available_models = sorted(fetched)
        except Exception as e:
            st.warning(f"API Key check failed: {e}")

    model_choice = st.selectbox("Cloud Model (Auto-Fetched)", available_models, index=0)
    st.divider()
    st.markdown("### 📊 System Architecture")
    st.info(
        "1. **Input:** User submits SMS/Email\n"
        "2. **Cloud Route:** Streamlit Cloud\n"
        "3. **AI Engine:** Groq Cloud LPU API\n"
        "4. **Output:** Risk Score & Sorted Folders"
    )

st.title("🛡️ AI-Powered Phishing Detector & Smart Inbox Sorter")
st.markdown("Real-time cloud classification for suspicious SMS, emails, and links.")

tab1, tab2 = st.tabs(["🔍 Single Message Analyzer", "📥 Batch Email & SMS Sorter"])

with tab1:
    st.subheader("Analyze a Suspicious SMS, Email, or Link")
    col1, col2, col3 = st.columns(3)
    if col1.button("🚨 Load Bank Phishing SMS", use_container_width=True):
        st.session_state["single_input"] = (
            "URGENT: Your HDFC Bank NetBanking account has been suspended due to incomplete KYC. "
            "Update immediately within 2 hours or account will be blocked: [http://hdfc-kyc-verify-update.xyz/login](http://hdfc-kyc-verify-update.xyz/login)"
        )
    if col2.button("⚠️ Load Job/Lottery Scam", use_container_width=True):
        st.session_state["single_input"] = (
            "Congratulations! Your mobile number won ₹25,00,000 in the WhatsApp Lucky Draw 2026. "
            "To claim your prize, send your Aadhaar card copy and ₹2,500 processing fee to claim@prize-desk.in"
        )
    if col3.button("✅ Load Legitimate Alert", use_container_width=True):
        st.session_state["single_input"] = (
            "Hi Rahul, your appointment with Dr. Sharma at Apollo Clinic is confirmed for tomorrow at 10:30 AM. "
            "Reply C to confirm or call 080-26304050 to reschedule."
        )

    user_message = st.text_area("Paste message content below:", key="single_input", height=140)

    if st.button("Analyze Threat Level", type="primary"):
        if not api_key or model_choice == "Enter API key above to load models":
            st.error("Please enter a valid Groq API Key in the left sidebar first.")
        elif not user_message.strip():
            st.warning("Please click a sample button or paste a message first.")
        else:
            client = Groq(api_key=api_key)
            with st.spinner("Analyzing message via Cloud AI..."):
                try:
                    schema_str = json.dumps(SingleAnalysisResult.model_json_schema())
                    completion = client.chat.completions.create(
                        model=model_choice,
                        messages=[
                            {"role": "system", "content": f"You are a cybersecurity analyst. Respond ONLY with valid JSON matching: {schema_str}"},
                            {"role": "user", "content": f"Analyze this message:\n{user_message}"}
                        ],
                        temperature=0.1,
                    )
                    result = SingleAnalysisResult.model_validate_json(extract_json(completion.choices[0].message.content))

                    st.divider()
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Classification", result.category)
                    m2.metric("Threat Risk Score", f"{result.risk_score} / 100")
                    m3.metric("Recommended Action", result.recommended_action)

                    if result.risk_score >= 70:
                        st.error(f"**Verdict:** {result.explanation}")
                    elif result.risk_score >= 35:
                        st.warning(f"**Verdict:** {result.explanation}")
                    else:
                        st.success(f"**Verdict:** {result.explanation}")

                    if result.red_flags:
                        st.markdown("**🚩 Detected Red Flags:**")
                        for flag in result.red_flags:
                            st.markdown(f"- {flag}")
                    else:
                        st.markdown("**✅ No phishing indicators or malicious patterns detected.**")
                except Exception as e:
                    st.error(f"Cloud API Error: {e}")

with tab2:
    st.subheader("Automatically Sort Multiple Emails & SMS into Folders")
    default_batch = (
        "1. From: HR Dept | Subject: Interview Schedule for Thursday at 2 PM via Google Meet.\n"
        "2. From: +91-9822100112 | SMS: Dear Customer, your electricity power will be disconnected tonight at 9:30 PM because previous bill was not updated. Call 9822100112 immediately.\n"
        "3. From: Myntra Offers | Subject: Flat 60% OFF End of Reason Sale! Shop sneakers & jackets today only.\n"
        "4. From: support@paypa1-security-alert.com | Subject: Unusual sign-in detected. Click here to verify your password now.\n"
        "5. From: IRCTC | SMS: PNR 4521890123 Confirmed. Train 12627 Karnataka Exp, Coach B2, Seat 34."
    )
    batch_input = st.text_area("Enter multiple messages (one per line):", value=default_batch, height=180)

    if st.button("Sort Inbox Messages", type="primary"):
        if not api_key or model_choice == "Enter API key above to load models":
            st.error("Please enter a valid Groq API Key in the left sidebar first.")
        elif not batch_input.strip():
            st.warning("Please enter messages to sort.")
        else:
            client = Groq(api_key=api_key)
            with st.spinner("Sorting messages via Cloud AI..."):
                try:
                    schema_str = json.dumps(BatchSortResult.model_json_schema())
                    completion = client.chat.completions.create(
                        model=model_choice,
                        messages=[
                            {"role": "system", "content": f"Sort each numbered message into 'Primary (Safe)', 'Promotions / Spam', or 'Quarantine (Phishing)'. Respond ONLY with valid JSON matching: {schema_str}"},
                            {"role": "user", "content": batch_input}
                        ],
                        temperature=0.1,
                    )
                    batch_data = BatchSortResult.model_validate_json(extract_json(completion.choices[0].message.content))
                    df = pd.DataFrame([item.model_dump() for item in batch_data.sorted_messages])

                    c1, c2, c3 = st.columns(3)
                    c1.metric("✅ Primary (Safe)", len(df[df["folder"] == "Primary (Safe)"]))
                    c2.metric("📢 Promotions / Spam", len(df[df["folder"] == "Promotions / Spam"]))
                    c3.metric("🚨 Quarantine (Phishing)", len(df[df["folder"] == "Quarantine (Phishing)"]))

                    st.dataframe(
                        df,
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "id": "ID",
                            "sender_or_preview": "Message Summary",
                            "folder": "Assigned Folder",
                            "risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
                            "reason": "AI Reasoning"
                        }
                    )
                except Exception as e:
                    st.error(f"Cloud API Error: {e}")