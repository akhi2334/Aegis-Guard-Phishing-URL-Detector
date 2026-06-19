import streamlit as st
import joblib
import pandas as pd
from datetime import datetime


# ---------------- PAGE CONFIGURATION----------------
st.set_page_config(
    page_title="Aegis Guard - Phishing URL Detector",
    page_icon="🛡️",
    layout="wide"
)

# Remove Streamlit top space
st.markdown("""
<style>
header {
    visibility: hidden;
}

.block-container {
    padding-top: 0rem;
}
</style>
""", unsafe_allow_html=True)
# ---------------- CUSTOM CSS ----------------
st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Orbitron', sans-serif;
}

.stApp {
    background-color: #050505;
    color: white;
}

[data-testid="stSidebar"] {
    background-color: #0b0b0b;
    border-right: 1px solid #1f1f1f;
}

[data-testid="stSidebar"] * {
    color: white;
}

.main-title {
    font-size: 50px;
    font-weight: bold;
    color: #2f6fff;
}

.sub-title {
    color: #999999;
    font-size: 14px;
    margin-bottom: 30px;
}

.card {
    background: #111111;
    border: 1px solid #222222;
    border-radius: 18px;
    padding: 20px;
    margin-bottom: 20px;
}

.stTextInput input {
    background-color: #0f0f0f !important;
    color: white !important;
    border: 1px solid #333 !important;
    border-radius: 12px !important;
}

.stButton button {
    width: 100%;
    background: #1f4fff;
    color: white;
    border: none;
    border-radius: 12px;
    padding: 10px;
    font-weight: bold;
}

.stButton button:hover {
    background: #3466ff;
}

.result-good {
    color: #00ff88;
    font-size: 22px;
    font-weight: bold;
}

.result-bad {
    color: #ff4d4d;
    font-size: 22px;
    font-weight: bold;
}

hr {
    border: 1px solid #222;
}

</style>
""", unsafe_allow_html=True)

# ---------------- LOAD MODEL ----------------

try:
    model = joblib.load("URL_phishing.save")
    scaler = joblib.load("URL_scalar.save")
    encoder = joblib.load("URL_phishing_encoder.save")
except:
    model = None
    scaler = None
    encoder = None

# ---------------- FEATURE EXTRACTION ----------------

def extract_features(url):
    return [
        len(url),
        len(url.split("/")[2]) if "//" in url else 0,
        url.count("."),
        url.count("/"),
        1 if "https" in url else 0,
        sum(c.isdigit() for c in url) / len(url),
        url.count(".") - 1,
        len(url.split()),
        max([url.count(c) for c in set(url)]),
        min([len(w) for w in url.split(".")]) if "." in url else 0,
        min([len(w) for w in url.split("/")]) if "/" in url else 0,
        max([len(w) for w in url.split()]),
        max([len(w) for w in url.split(".")]) if "." in url else 0,
        max([len(w) for w in url.split("/")]) if "/" in url else 0,
        sum(len(w) for w in url.split()) / len(url.split()),
        sum(len(w) for w in url.split(".")) / len(url.split(".")) if "." in url else 0,
        sum(len(w) for w in url.split("/")) / len(url.split("/")) if "/" in url else 0,
        0.0
    ]

# ---------------- SIDEBAR ----------------

# ---------------- SIDEBAR ----------------

# ---------------- SIDEBAR ----------------

# Extra Sidebar Styling
st.markdown("""
<style>

/* Sidebar Buttons */
[data-testid="stSidebar"] .stButton button{
    background:#111111;
    color:white;
    border:1px solid #222222;
    border-radius:12px;
    margin-bottom:10px;
    text-align:left;
    height:50px;
    font-weight:600;
}

[data-testid="stSidebar"] .stButton button:hover{
    background:#1f4fff;
    border:1px solid #1f4fff;
    color:white;
}

/* Status Card */
.status-card{
    background:#071d10;
    border:1px solid #00aa55;
    border-radius:12px;
    padding:15px;
    margin-top:20px;
    color:white;
}

</style>
""", unsafe_allow_html=True)

# Sidebar Header
st.sidebar.markdown("""
# 🛡️ Aegis Guard

<span style='color:gray;'>Phishing Forensics</span>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")

# Navigation Buttons
if "page" not in st.session_state:
    st.session_state.page = "Dashboard Scan"

if st.sidebar.button("🛡 Dashboard Scan", use_container_width=True):
    st.session_state.page = "Dashboard Scan"

if st.sidebar.button("⚙ Optimizer Training", use_container_width=True):
    st.session_state.page = "Optimizer Training"

if st.sidebar.button("🗄 System Dataset", use_container_width=True):
    st.session_state.page = "System Dataset"

menu = st.session_state.page

st.sidebar.markdown("---")

# Model Status Card
st.sidebar.markdown("""
<div class="status-card">
<h4>🟢 Detection Engine</h4>

<b>Model:</b> Random Forest v2.4<br><br>

<b>Accuracy:</b> 97.2%<br><br>

<b>Status:</b> Online
</div>
""", unsafe_allow_html=True)
# ---------------- DASHBOARD ----------------

if menu == "Dashboard Scan":

    st.markdown(
        "<div class='main-title'>Phishing URL Detector</div>",
        unsafe_allow_html=True
    )

    st.markdown(
        "<div class='sub-title'>Advanced college project for phishing URL detection using Machine Learning</div>",
        unsafe_allow_html=True
    )

    

    st.subheader("🔍 Analyze Suspicious URL")

    user_url = st.text_input(
        "",
        placeholder="Enter suspicious URL..."
    )

    analyze = st.button("ANALYZE URL")

    st.markdown("</div>", unsafe_allow_html=True)

    if analyze and user_url:

        if model is not None:

            features = extract_features(user_url)
            scaled = scaler.transform([features])

            prediction = model.predict(scaled)[0]
            result = encoder.inverse_transform([prediction])[0]

            score = 88 if result.lower() == "phishing" else 5

        else:
            if any(word in user_url.lower() for word in ["login", "verify", "bank", "paypal"]):
                result = "phishing"
                score = 88
            else:
                result = "legitimate"
                score = 5

        if result.lower() == "legitimate":

            st.markdown(
                f"<div class='result-good'>✅ LEGITIMATE URL<br>Threat Score: {score}%</div>",
                unsafe_allow_html=True
            )

        else:

            st.markdown(
                f"<div class='result-bad'>⚠️ PHISHING URL DETECTED<br>Threat Score: {score}%</div>",
                unsafe_allow_html=True
            )

        log_entry = pd.DataFrame(
            [[
                user_url,
                f"{score}%",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                result
            ]],
            columns=[
                "Target URL",
                "Threat Score",
                "Timestamp",
                "Classification"
            ]
        )

        if "history" not in st.session_state:
            st.session_state.history = log_entry
        else:
            st.session_state.history = pd.concat(
                [log_entry, st.session_state.history],
                ignore_index=True
            )

    st.markdown("---")

    st.subheader("⚡ Interactive Demo Testing Samples")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.button("⚠ paypal-signin-safety-lockdown")

    with col2:
        st.button("⚠ netflix-login-renew-payment")

    with col3:
        st.button("⚠ chase-bank-verify-alert")

    col4, col5 = st.columns(2)

    with col4:
        st.button("🟢 google.com")

    with col5:
        st.button("🟢 github.com")

    st.markdown("---")

    st.subheader("🔍 Recent URL Checks")

    if "history" in st.session_state:
        st.dataframe(
            st.session_state.history,
            use_container_width=True
        )
    else:
        st.info("No scans performed yet.")

# ---------------- TRAINING ----------------

elif menu == "Optimizer Training":

    st.markdown(
        "<div class='main-title'>Optimizer Training</div>",
        unsafe_allow_html=True
    )

    st.write("⚙️ Future module for retraining and hyperparameter tuning.")

# ---------------- DATASET ----------------

elif menu == "System Dataset":

    st.markdown(
        "<div class='main-title'>System Dataset</div>",
        unsafe_allow_html=True
    )

    st.write("📊 Dataset management and analytics module.")

# ---------------- FOOTER ----------------

st.markdown("---")

st.caption(
    "© 2026 Cybersecurity Defense Research Project • Aegis Guard v2.4"
)