import streamlit as st
import json

# 1. Read API Key safely from Streamlit Cloud Secrets or Colab Secrets
groq_api_key = st.secrets.get("GROQ_API_KEY", None)

if not groq_api_key:
    try:
        from google.colab import userdata
        groq_api_key = userdata.get('GROQ_API_KEY')
    except Exception:
        groq_api_key = None

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

# Page Configuration
st.set_page_config(
    page_title="CyberShield AI | Phishing Detection Studio",
    page_icon="🛡️",
    layout="wide"
)

# High-Contrast UI Styling
st.markdown("""
<style>
    .stApp { background-color: #0b0f19; color: #f1f5f9; }
    .main .block-container { padding-top: 1.5rem; max-width: 95%; }
    
    .header-banner {
        background: linear-gradient(90deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-left: 5px solid #38bdf8;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 25px;
    }

    .cyber-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 20px;
    }

    .card-title {
        font-size: 14px;
        font-weight: 700;
        text-transform: uppercase;
        color: #38bdf8;
        margin-bottom: 15px;
    }

    .badge { padding: 15px; border-radius: 8px; text-align: center; font-weight: 800; margin-bottom: 15px; }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
    .badge-warning { background-color: rgba(245, 158, 11, 0.2); border: 1px solid #f59e0b; color: #fde68a; }
    .badge-safe { background-color: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; color: #a7f3d0; }

    .threat-item {
        background: rgba(15, 23, 42, 0.6);
        border-left: 3px solid #ef4444;
        padding: 10px;
        border-radius: 4px;
        margin-bottom: 8px;
        font-size: 13px;
    }

    .stTextInput label, .stTextArea label {
        color: #ffffff !important;
        font-weight: 700 !important;
        font-size: 14px !important;
    }

    .stTextInput input, .stTextArea textarea {
        background-color: #0f172a !important;
        color: #f8fafc !important;
        border: 1px solid #475569 !important;
        border-radius: 8px !important;
    }

    .stTextInput input::placeholder, .stTextArea textarea::placeholder {
        color: #94a3b8 !important;
        opacity: 1 !important;
    }

    .stButton button {
        background: linear-gradient(90deg, #0284c7 0%, #2563eb 100%) !important;
        color: white !important;
        font-weight: 700 !important;
        border: none !important;
        width: 100% !important;
        padding: 10px !important;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="header-banner">
    <div style="font-size: 26px; font-weight: 800; color: #f8fafc;">🛡️ CyberShield AI Studio</div>
    <div style="color: #94a3b8; font-size: 13px;">Automated LLM & Heuristic Threat Intelligence</div>
</div>
""", unsafe_allow_html=True)

# Local Heuristics Fallback Engine
def run_local_heuristics(sender, subject, body):
    score = 0
    reasons = []
    text = f"{subject} {body}".lower()
    
    if any(k in text for k in ["verify", "password", "urgent", "bank", "login", "suspended", "otp"]):
        score += 40
        reasons.append("High-risk phishing keywords detected in subject or body.")
    if "http://" in body or "bit.ly" in body or "tinyurl" in body:
        score += 35
        reasons.append("Unsecured (HTTP) or shortened link detected.")
    if sender and any(tld in sender.lower() for tld in [".xyz", ".tk", ".ml", "tempmail"]):
        score += 25
        reasons.append(f"Suspicious sender domain detected: '{sender}'")
        
    score = min(max(score, 0), 100)
    
    if score >= 70:
        return "Phishing Attack", score, "CRITICAL THREAT (Local)", "badge-critical", reasons
    elif score >= 40:
        return "Suspicious Email", score, "ELEVATED RISK (Local)", "badge-warning", reasons
    else:
        return "Legitimate Email", score, "LOW RISK (Local)", "badge-safe", ["No threat patterns detected."]

# Groq LLM Engine
def analyze_threat(sender, subject, body):
    if not GROQ_AVAILABLE or not groq_api_key:
        return run_local_heuristics(sender, subject, body)
    
    models_to_try = ["llama-3.3-70b-versatile", "llama3-70b-8192", "llama-3.1-8b-instant"]
    
    for model_name in models_to_try:
        try:
            client = Groq(api_key=groq_api_key)
            system_prompt = 'You are a Cybersecurity Expert Analyst. Analyze the email provided. Return ONLY JSON matching: {"classification": "Phishing Attack" OR "Suspicious Email" OR "Legitimate Email", "score": integer 0-100, "threat_level": "CRITICAL THREAT" OR "ELEVATED RISK" OR "LOW RISK", "reasons": ["reason 1"]}'
            user_prompt = f"Sender: {sender}\nSubject: {subject}\nBody: {body}"
            
            response = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                response_format={"type": "json_object"}
            )
            
            data = json.loads(response.choices[0].message.content)
            score = data.get("score", 50)
            classification = data.get("classification", "Analyzed")
            level = data.get("threat_level", "GROQ ANALYZED")
            reasons = data.get("reasons", ["LLM evaluation completed."])
            
            badge = "badge-critical" if score >= 70 else ("badge-warning" if score >= 40 else "badge-safe")
            return classification, score, level, badge, reasons
        except Exception:
            continue
            
    return run_local_heuristics(sender, subject, body)

col_input, col_results = st.columns([1.1, 0.9], gap="medium")

with col_input:
    st.markdown('<div class="cyber-card"><div class="card-title">📥 Message Vector Inspection</div>', unsafe_allow_html=True)
    sender_input = st.text_input("Sender Email Address", placeholder="security-alert@verify-bank.xyz")
    subject_input = st.text_input("Subject Line Header", placeholder="URGENT: Account Access Suspended")
    body_input = st.text_area("Full Email Body Content", height=200, placeholder="Paste email content here...")
    analyze_btn = st.button("⚡ EXECUTE THREAT ANALYSIS")
    st.markdown('</div>', unsafe_allow_html=True)

with col_results:
    if analyze_btn:
        if not sender_input and not subject_input and not body_input:
            st.warning("⚠️ Please fill in at least one field to analyze.")
        else:
            with st.spinner("Analyzing threat vectors..."):
                classification, score, level, badge, reasons = analyze_threat(sender_input, subject_input, body_input)

                st.markdown(f'''
                <div class="cyber-card">
                    <div class="card-title">📊 Diagnostic Summary</div>
                    <div class="badge {badge}">
                        <div style="font-size: 11px; opacity: 0.8;">{classification}</div>
                        <div style="font-size: 20px; font-weight: 800; margin-top: 4px;">{level}</div>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 13px; color: #94a3b8;">
                        <span>Threat Score Rating</span>
                        <span style="font-weight: 700; color: #f8fafc;">{score} / 100</span>
                    </div>
                </div>
                
                <div class="cyber-card">
                    <div class="card-title">🚨 Detected Risk Indicators</div>
                ''', unsafe_allow_html=True)

                for r in reasons:
                    st.markdown(f'<div class="threat-item">⚠️ {r}</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.markdown('''
        <div class="cyber-card" style="text-align: center; padding: 40px 20px;">
            <div style="font-size: 36px; margin-bottom: 8px;">🛡️</div>
            <div style="font-weight: 700; color: #f8fafc;">System Standby</div>
            <div style="font-size: 12px; color: #64748b; margin-top: 4px;">Enter details on the left and click Execute.</div>
        </div>
        ''', unsafe_allow_html=True)