import streamlit as st

from detector import audit_text


st.set_page_config(
    page_title="Shadow AI Privacy Auditor",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem; padding-bottom: 2rem;}
    .hero {
        padding: 1.2rem 1.4rem;
        border-radius: 16px;
        background: linear-gradient(135deg, rgba(40,90,255,.12), rgba(0,180,160,.10));
        border: 1px solid rgba(128,128,128,.25);
        margin-bottom: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <h1>🛡️ Shadow AI Privacy Auditor</h1>
      <p>Detect and redact sensitive information before sharing text with an AI tool.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.info(
    "This demo uses local rule-based detection and does not require an external AI API. "
    "Use fictional test data in public demonstrations."
)

sample_text = """Hello, my email is ravi@example.com.
Call me at +1 415-555-2671.
My test card is 4111 1111 1111 1111.
The development server IP is 192.168.1.20.
password=SuperSecret123
"""

with st.sidebar:
    st.header("About")
    st.write(
        "Shadow AI can expose private data when people paste sensitive content into "
        "unapproved AI tools. This app checks text first."
    )
    st.subheader("Detected categories")
    st.write(
        "Email, phone, payment card, IPv4, Aadhaar, AWS access key, JWT, API key, and password."
    )
    st.caption("Built with Python and Streamlit.")

text = st.text_area(
    "Text to audit",
    value=sample_text,
    height=260,
    placeholder="Paste text before sending it to an AI assistant...",
)

scan = st.button("Scan for privacy risks", type="primary", use_container_width=True)

if scan:
    if not text.strip():
        st.warning("Enter some text before scanning.")
    else:
        detections, redacted_text, risk_score = audit_text(text)

        metric1, metric2, metric3 = st.columns(3)
        metric1.metric("Detections", len(detections))
        metric2.metric("Risk score", f"{risk_score}/100")
        metric3.metric("Status", "Review required" if detections else "Safe")

        if detections:
            st.error(f"Found {len(detections)} possible privacy risk(s).")
            rows = [
                {
                    "Category": item.category,
                    "Detected value": item.value,
                    "Confidence": item.confidence,
                    "Why risky": item.risk,
                    "Replacement": item.replacement,
                }
                for item in detections
            ]
            st.subheader("Detection details")
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.success("No supported sensitive information was detected.")

        left, right = st.columns(2)

        with left:
            st.subheader("Original text")
            st.text_area(
                "Original text output",
                value=text,
                height=260,
                disabled=True,
                label_visibility="collapsed",
            )

        with right:
            st.subheader("Redacted text")
            st.text_area(
                "Redacted text output",
                value=redacted_text,
                height=260,
                label_visibility="collapsed",
            )

        st.download_button(
            "Download redacted text",
            data=redacted_text,
            file_name="redacted_text.txt",
            mime="text/plain",
            use_container_width=True,
        )

st.divider()
st.subheader("How it works")
st.write(
    "The app scans text using transparent regular-expression rules. "
    "Credit-card candidates are verified with the Luhn algorithm, invalid IPv4 "
    "addresses are rejected, overlapping findings are removed, and redactions are "
    "applied from right to left so text positions stay correct."
)

st.caption(
    "Limitations: rule-based detection can miss context-dependent confidential information "
    "and may still produce false positives. This is a demonstration, not a certified DLP system."
)

