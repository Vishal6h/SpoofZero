import os
import tempfile
import textwrap
import streamlit as st

from backend.analyze import analyze_email
from frontend.case_ui import render_case_workspace, render_case_report


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="SpoofZero",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# CUSTOM UI
# ============================================================

st.markdown("""
<style>

    /* Main app */
    .stApp {
        background:
            radial-gradient(circle at top right, rgba(25, 90, 150, 0.12), transparent 25%),
            linear-gradient(180deg, #071018 0%, #09141d 100%);
    }

    .block-container {
        max-width: 1450px;
        padding-top: 2rem;
        padding-bottom: 4rem;
    }

    /* Remove Streamlit clutter */
    #MainMenu {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }

    header {
        background: transparent !important;
    }

    /* Brand */
    .brand-wrapper {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1.2rem 1.4rem;
        margin-bottom: 1.2rem;
        border: 1px solid rgba(120, 170, 210, 0.15);
        border-radius: 18px;
        background: rgba(10, 23, 34, 0.82);
        backdrop-filter: blur(15px);
        box-shadow: 0 14px 40px rgba(0,0,0,0.25);
    }

    .brand-name {
        font-size: 2rem;
        font-weight: 800;
        letter-spacing: -0.04em;
        margin: 0;
    }

    .brand-zero {
        color: #4db8ff;
    }

    .brand-tagline {
        margin-top: 0.2rem;
        color: #8da0ae;
        font-size: 0.92rem;
    }

    .engine-status {
        padding: 0.45rem 0.8rem;
        border-radius: 999px;
        border: 1px solid rgba(75, 200, 140, 0.28);
        background: rgba(75, 200, 140, 0.08);
        color: #74dca5;
        font-size: 0.82rem;
        font-weight: 600;
    }

    /* Upload panel */
    .upload-panel {
        padding: 1.4rem 1.6rem;
        border-radius: 18px;
        border: 1px solid rgba(120, 170, 210, 0.13);
        background: rgba(11, 24, 35, 0.78);
        margin-bottom: 1rem;
    }

    .upload-title {
        font-size: 1.15rem;
        font-weight: 700;
    }

    .upload-subtitle {
        color: #8194a2;
        font-size: 0.88rem;
        margin-top: 0.2rem;
    }

    /* Metric cards */
    .sz-card {
        border: 1px solid rgba(120, 170, 210, 0.14);
        background: linear-gradient(
            145deg,
            rgba(14, 30, 43, 0.94),
            rgba(9, 21, 31, 0.94)
        );
        border-radius: 16px;
        padding: 1.15rem 1.2rem;
        min-height: 118px;
        box-shadow: 0 12px 28px rgba(0,0,0,0.18);
    }

    .sz-label {
        color: #8194a2;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-size: 0.72rem;
        font-weight: 700;
    }

    .sz-value {
        font-size: 1.75rem;
        margin-top: 0.4rem;
        font-weight: 800;
    }

    .sz-small {
        margin-top: 0.35rem;
        color: #758997;
        font-size: 0.8rem;
    }

    /* Section titles */
    .section-title {
        font-size: 1.05rem;
        font-weight: 750;
        margin-top: 1.3rem;
        margin-bottom: 0.65rem;
    }

    /* Verdict badges */
    .verdict-critical {
        color: #ff6d7a;
    }

    .verdict-high {
        color: #ffad66;
    }

    .verdict-suspicious {
        color: #ffd86b;
    }

    .verdict-safe {
        color: #70dda3;
    }

    /* Reason panel */
    .reason-box {
        border-left: 3px solid #4db8ff;
        background: rgba(77, 184, 255, 0.06);
        padding: 0.75rem 0.9rem;
        border-radius: 8px;
        margin-bottom: 0.55rem;
        color: #d8e2e9;
    }

    /* Authentication badges */
    .auth-pass {
        display: inline-block;
        padding: 0.35rem 0.75rem;
        border-radius: 999px;
        color: #6fdda2;
        background: rgba(71, 200, 130, 0.08);
        border: 1px solid rgba(71, 200, 130, 0.20);
        font-weight: 700;
    }

    .auth-fail {
        display: inline-block;
        padding: 0.35rem 0.75rem;
        border-radius: 999px;
        color: #ff7f88;
        background: rgba(255, 90, 100, 0.07);
        border: 1px solid rgba(255, 90, 100, 0.18);
        font-weight: 700;
    }

    .auth-unknown {
        display: inline-block;
        padding: 0.35rem 0.75rem;
        border-radius: 999px;
        color: #f1c96f;
        background: rgba(230, 180, 70, 0.07);
        border: 1px solid rgba(230, 180, 70, 0.18);
        font-weight: 700;
    }

    /* Tables */
    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(120, 170, 210, 0.13);
        border-radius: 12px;
        overflow: hidden;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background: rgba(10, 23, 34, 0.60);
        border-radius: 12px;
        padding: 0.35rem;
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 9px;
        padding: 0.5rem 0.9rem;
    }

    /* Buttons */
    .stButton > button {
        border-radius: 10px;
        font-weight: 700;
        min-height: 44px;
    }

    /* Expander */
    details {
        border-radius: 12px !important;
    }

</style>
""", unsafe_allow_html=True)


# ============================================================
# HELPERS
# ============================================================

def render_html(content):
    st.markdown(
        textwrap.dedent(content).strip(),
        unsafe_allow_html=True
    )


def card(label, value, note="", value_class=""):
    render_html(
        f"""
        <div class="sz-card">
            <div class="sz-label">{label}</div>
            <div class="sz-value {value_class}">{value}</div>
            <div class="sz-small">{note}</div>
        </div>
        """
    )


def verdict_class(verdict):
    verdict = (verdict or "").upper()

    if verdict == "CRITICAL":
        return "verdict-critical"

    if verdict == "HIGH RISK":
        return "verdict-high"

    if verdict in ("SUSPICIOUS", "REVIEW REQUIRED", "INCONCLUSIVE"):
        return "verdict-suspicious"

    return "verdict-safe"


def auth_badge(value):
    value = (value or "unknown").upper()

    if value == "PASS":
        css = "auth-pass"

    elif value in ("FAIL", "SOFTFAIL"):
        css = "auth-fail"

    else:
        css = "auth-unknown"

    return f'<span class="{css}">{value}</span>'


# ============================================================
# HEADER
# ============================================================

render_html(
    """
    <div class="brand-wrapper">
        <div>
            <div class="brand-name">Spoof<span class="brand-zero">Zero</span></div>
            <div class="brand-tagline">AI Email Threat Detection &amp; Forensic Intelligence</div>
        </div>
        <div class="engine-status">● ANALYSIS ENGINE ONLINE</div>
    </div>
    """
)


# ============================================================
# UPLOAD
# ============================================================

render_html(
    """
    <div class="upload-panel">
        <div class="upload-title">Investigate an Email</div>
        <div class="upload-subtitle">Upload a raw .EML file to begin forensic analysis.</div>
    </div>
    """
)


uploaded_file = st.file_uploader(
    "Choose an EML file",
    type=["eml"],
    label_visibility="collapsed"
)


if uploaded_file is not None:

    file_col, button_col = st.columns(
        [5, 1],
        vertical_alignment="center"
    )

    with file_col:
        st.success(
            f"Loaded: {uploaded_file.name}"
        )

    with button_col:
        analyze_clicked = st.button(
            "Analyze",
            use_container_width=True,
            type="primary"
        )

    if analyze_clicked:

        temp_path = None

        try:

            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".eml"
            ) as temp_file:

                temp_file.write(
                    uploaded_file.getvalue()
                )

                temp_path = temp_file.name

            with st.spinner(
                "SpoofZero is correlating forensic evidence..."
            ):

                result = analyze_email(
                    temp_path
                )

            st.session_state["spoofzero_result"] = result
            st.session_state["spoofzero_filename"] = uploaded_file.name

        finally:

            if (
                temp_path
                and os.path.exists(temp_path)
            ):
                os.unlink(
                    temp_path
                )


case_workspace = render_case_workspace()


# ============================================================
# RESULTS
# ============================================================

result = st.session_state.get(
    "spoofzero_result"
)

if result:

    assessment = result.get(
        "final_assessment",
        {}
    )

    ai = result.get(
        "ai_analysis",
        {}
    )

    sender = result.get(
        "sender_identity",
        {}
    )

    auth = result.get(
        "authentication",
        {}
    )

    relay = result.get(
        "relay_trace",
        {}
    )

    geo = result.get(
        "geo_analysis",
        {}
    )

    iocs = result.get(
        "iocs",
        {}
    )

    # --------------------------------------------------------
    # SUMMARY CARDS
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Investigation Summary</div>',
        unsafe_allow_html=True
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        card(
            "Threat Score",
            f'{assessment.get("risk_score", 0)}/100',
            "Composite forensic risk"
        )

    with c2:
        verdict = assessment.get(
            "verdict",
            "UNKNOWN"
        )

        card(
            "Verdict",
            verdict,
            "SpoofZero final assessment",
            verdict_class(verdict)
        )

    with c3:
        card(
            "AI Probability",
            f'{ai.get("phishing_probability", 0)}%',
            ai.get(
                "verdict",
                "No AI verdict"
            )
        )

    with c4:
        card(
            "Relay Hops",
            relay.get(
                "hop_count",
                0
            ),
            "SMTP path reconstructed"
        )


    # --------------------------------------------------------
    # EMAIL IDENTITY BAR
    # --------------------------------------------------------

    email_info = result.get(
        "email",
        {}
    )

    st.caption(
        f'File: {st.session_state.get("spoofzero_filename", "Unknown")}   •   '
        f'Subject: {email_info.get("subject") or "Unknown"}   •   '
        f'From: {email_info.get("from") or "Unknown"}'
    )


    # --------------------------------------------------------
    # TABS
    # --------------------------------------------------------

    overview_tab, forensic_tab, intel_tab, attachment_tab, raw_tab, campaign_tab = st.tabs(
        [
            "Overview",
            "Email Forensics",
            "Threat Intelligence",
            "Attachments",
            "Raw Evidence",
            "Campaign / Cases"
        ]
    )


    # ========================================================
    # OVERVIEW
    # ========================================================

    with overview_tab:

        st.markdown(
            '<div class="section-title">Why SpoofZero flagged this email</div>',
            unsafe_allow_html=True
        )

        reasons = assessment.get(
            "reasons",
            []
        )

        if reasons:

            for reason in reasons:

                st.markdown(
                    f'<div class="reason-box">{reason}</div>',
                    unsafe_allow_html=True
                )

        else:

            st.success(
                "No major threat indicators were detected."
            )


        st.markdown(
            '<div class="section-title">Authentication</div>',
            unsafe_allow_html=True
        )

        a1, a2, a3 = st.columns(3)

        with a1:

            st.markdown(
                f"""
                <div class="sz-card">
                    <div class="sz-label">SPF</div>
                    <br>
                    {auth_badge(auth.get("spf"))}
                </div>
                """,
                unsafe_allow_html=True
            )

        with a2:

            st.markdown(
                f"""
                <div class="sz-card">
                    <div class="sz-label">DKIM</div>
                    <br>
                    {auth_badge(auth.get("dkim"))}
                </div>
                """,
                unsafe_allow_html=True
            )

        with a3:

            st.markdown(
                f"""
                <div class="sz-card">
                    <div class="sz-label">DMARC</div>
                    <br>
                    {auth_badge(auth.get("dmarc"))}
                </div>
                """,
                unsafe_allow_html=True
            )


        evidence_scores = assessment.get(
            "evidence_scores",
            {}
        )

        if evidence_scores:

            st.markdown(
                '<div class="section-title">Evidence Scores</div>',
                unsafe_allow_html=True
            )

            st.dataframe(
                {
                    "Evidence": [
                        "Sender Identity",
                        "Authentication",
                        "AI / NLP",
                        "Threat Reputation",
                        "Attachment Reputation"
                    ],

                    "Score": [
                        evidence_scores.get(
                            "sender_identity",
                            0
                        ),
                        evidence_scores.get(
                            "authentication",
                            0
                        ),
                        evidence_scores.get(
                            "ai_phishing",
                            0
                        ),
                        evidence_scores.get(
                            "threat_reputation",
                            0
                        ),
                        evidence_scores.get(
                            "attachment_reputation",
                            0
                        )
                    ]
                },

                hide_index=True,
                use_container_width=True
            )


    # ========================================================
    # EMAIL FORENSICS
    # ========================================================

    with forensic_tab:

        st.markdown(
            '<div class="section-title">Sender Identity</div>',
            unsafe_allow_html=True
        )

        sender_table = {
            "Field": [
                "From Domain",
                "Reply-To Domain",
                "Return-Path Domain",
                "Identity Risk"
            ],

            "Value": [
                sender.get(
                    "from_domain"
                ),
                sender.get(
                    "reply_to_domain"
                ),
                sender.get(
                    "return_path_domain"
                ),
                f'{sender.get("risk_score", 0)}/100'
            ]
        }

        st.dataframe(
            sender_table,
            hide_index=True,
            use_container_width=True
        )


        st.markdown(
            '<div class="section-title">Indicators of Compromise</div>',
            unsafe_allow_html=True
        )

        ioc_tabs = st.tabs(
            [
                "URLs",
                "IPs",
                "Domains",
                "Emails"
            ]
        )

        categories = [
            "urls",
            "ips",
            "domains",
            "emails"
        ]

        for tab, category in zip(
            ioc_tabs,
            categories
        ):

            with tab:

                values = iocs.get(
                    category,
                    []
                )

                if values:

                    st.dataframe(
                        {
                            "Indicator": values
                        },
                        hide_index=True,
                        use_container_width=True
                    )

                else:

                    st.info(
                        "No indicators found."
                    )


        st.markdown(
            '<div class="section-title">SMTP Relay Reconstruction</div>',
            unsafe_allow_html=True
        )

        origin_ip = relay.get(
            "candidate_origin_ip"
        )

        if origin_ip:

            st.success(
                f"Candidate origin infrastructure IP: {origin_ip}"
            )

        else:

            st.info(
                "No reliable public origin IP was identified."
            )


        for hop in relay.get(
            "hops",
            []
        ):

            title = (
                f'Hop {hop.get("hop_number")}   '
                f'{hop.get("from_host")}  →  '
                f'{hop.get("by_host")}'
            )

            with st.expander(
                title
            ):

                h1, h2, h3 = st.columns(3)

                with h1:

                    st.metric(
                        "Trust",
                        f'{hop.get("trust_score", 0)}/100'
                    )

                with h2:

                    st.metric(
                        "Chain Status",
                        hop.get(
                            "chain_status",
                            "UNKNOWN"
                        )
                    )

                with h3:

                    ip_list = [
                        x.get("ip")
                        for x in hop.get(
                            "ips",
                            []
                        )
                    ]

                    st.metric(
                        "IP Count",
                        len(ip_list)
                    )

                if hop.get(
                    "ips"
                ):

                    st.dataframe(
                        hop["ips"],
                        hide_index=True,
                        use_container_width=True
                    )


        st.markdown(
            '<div class="section-title">Origin Geo Intelligence</div>',
            unsafe_allow_html=True
        )

        if geo.get(
            "status"
        ) == "success":

            g1, g2, g3, g4 = st.columns(4)

            with g1:
                card(
                    "Country",
                    geo.get("country") or "Unknown"
                )

            with g2:
                card(
                    "Region",
                    geo.get("region") or "Unknown"
                )

            with g3:
                card(
                    "City Estimate",
                    geo.get("city") or "Unknown"
                )

            with g4:
                card(
                    "ASN",
                    geo.get("asn") or "Unknown"
                )

            st.write(
                "**ISP:**",
                geo.get("isp")
            )

            st.write(
                "**Organization:**",
                geo.get("organization")
            )

            lat = geo.get(
                "latitude"
            )

            lon = geo.get(
                "longitude"
            )

            if (
                lat is not None
                and lon is not None
            ):

                st.map(
                    [
                        {
                            "lat": lat,
                            "lon": lon
                        }
                    ]
                )

            st.warning(
                geo.get(
                    "confidence_note",
                    "Infrastructure location only."
                )
            )

        else:

            st.info(
                geo.get(
                    "message",
                    "Geo intelligence unavailable."
                )
            )


    # ========================================================
    # THREAT INTELLIGENCE
    # ========================================================

    with intel_tab:

        reputation = result.get(
            "reputation",
            {}
        )

        st.markdown(
            '<div class="section-title">VirusTotal Domain Reputation</div>',
            unsafe_allow_html=True
        )

        for item in reputation.get(
            "domains",
            []
        ):

            value = item.get(
                "value",
                "Unknown"
            )

            status = item.get(
                "status"
            )

            verdict = item.get(
                "verdict",
                status
            )

            with st.expander(
                f"{value}   •   {verdict}"
            ):

                if status == "success":

                    stats = item.get(
                        "analysis_stats",
                        {}
                    )

                    st.dataframe(
                        {
                            "Result": [
                                "Malicious",
                                "Suspicious",
                                "Harmless",
                                "Undetected"
                            ],

                            "Engines": [
                                stats.get(
                                    "malicious",
                                    0
                                ),
                                stats.get(
                                    "suspicious",
                                    0
                                ),
                                stats.get(
                                    "harmless",
                                    0
                                ),
                                stats.get(
                                    "undetected",
                                    0
                                )
                            ]
                        },

                        hide_index=True,
                        use_container_width=True
                    )

                elif status == "skipped":

                    st.info(
                        item.get(
                            "reason",
                            "Lookup skipped"
                        )
                    )

                else:

                    st.warning(
                        item.get(
                            "message",
                            "Lookup unavailable"
                        )
                    )


        st.markdown(
            '<div class="section-title">VirusTotal IP Reputation</div>',
            unsafe_allow_html=True
        )

        for item in reputation.get(
            "ips",
            []
        ):

            value = item.get(
                "value",
                "Unknown"
            )

            status = item.get(
                "status"
            )

            with st.expander(
                value
            ):

                if status == "success":

                    st.write(
                        "**Verdict:**",
                        item.get("verdict")
                    )

                    st.write(
                        "**Country:**",
                        item.get("country")
                    )

                    st.write(
                        "**ASN:**",
                        item.get("asn")
                    )

                    st.write(
                        "**Owner:**",
                        item.get("as_owner")
                    )

                    stats = item.get(
                        "analysis_stats",
                        {}
                    )

                    st.dataframe(
                        {
                            "Result": [
                                "Malicious",
                                "Suspicious",
                                "Harmless"
                            ],

                            "Engines": [
                                stats.get(
                                    "malicious",
                                    0
                                ),
                                stats.get(
                                    "suspicious",
                                    0
                                ),
                                stats.get(
                                    "harmless",
                                    0
                                )
                            ]
                        },

                        hide_index=True,
                        use_container_width=True
                    )

                else:

                    st.info(
                        item.get(
                            "reason"
                        )
                        or item.get(
                            "message"
                        )
                        or "Lookup unavailable"
                    )


        st.markdown(
            '<div class="section-title">DNS / RDAP Intelligence</div>',
            unsafe_allow_html=True
        )

        threat_data = result.get(
            "threat_intelligence",
            []
        )

        for domain_data in threat_data:

            domain = domain_data.get(
                "domain",
                "Unknown"
            )

            risk = domain_data.get(
                "risk_score",
                0
            )

            with st.expander(
                f"{domain}   •   Risk {risk}/100"
            ):

                if domain_data.get(
                    "status"
                ) == "reserved_demo":

                    st.info(
                        "Reserved demonstration domain. "
                        "Live lookup intentionally skipped."
                    )

                    continue

                dns_data = domain_data.get(
                    "dns",
                    {}
                )

                st.write(
                    "**A Records:**",
                    dns_data.get(
                        "A",
                        []
                    )
                )

                st.write(
                    "**MX Records:**",
                    dns_data.get(
                        "MX",
                        []
                    )
                )

                st.write(
                    "**Nameservers:**",
                    dns_data.get(
                        "NS",
                        []
                    )
                )

                rdap = domain_data.get(
                    "rdap",
                    {}
                )

                if rdap.get(
                    "status"
                ) == "success":

                    st.write(
                        "**Registered:**",
                        rdap.get(
                            "registration_date"
                        )
                    )

                    st.write(
                        "**Expires:**",
                        rdap.get(
                            "expiration_date"
                        )
                    )


    # ========================================================
    # ATTACHMENTS
    # ========================================================

    with attachment_tab:

        attachment_data = result.get(
            "attachments",
            {}
        )

        attachments = attachment_data.get(
            "attachments",
            []
        )

        st.markdown(
            f'<div class="section-title">Attachments Found: {len(attachments)}</div>',
            unsafe_allow_html=True
        )

        if not attachments:

            st.info(
                "No attachments were found."
            )

        else:

            reputation_by_hash = {
                x.get("value"): x
                for x in result.get(
                    "attachment_reputation",
                    []
                )
            }

            for attachment in attachments:

                filename = attachment.get(
                    "filename",
                    "Unnamed"
                )

                sha256 = attachment.get(
                    "sha256"
                )

                with st.expander(
                    filename
                ):

                    a1, a2 = st.columns(2)

                    with a1:

                        st.write(
                            "**Content Type**"
                        )

                        st.code(
                            attachment.get(
                                "content_type",
                                "Unknown"
                            )
                        )

                    with a2:

                        st.write(
                            "**Size**"
                        )

                        st.code(
                            f'{attachment.get("size_bytes", 0)} bytes'
                        )

                    st.write(
                        "**SHA-256 Fingerprint**"
                    )

                    st.code(
                        sha256 or ""
                    )

                    rep = reputation_by_hash.get(
                        sha256,
                        {}
                    )

                    if rep:

                        st.write(
                            "**Threat Reputation:**",
                            rep.get(
                                "verdict"
                            )
                            or rep.get(
                                "status"
                            )
                        )

                        if rep.get(
                            "status"
                        ) == "not_found":

                            st.info(
                                "Hash not found in VirusTotal. "
                                "Unknown does not mean safe."
                            )


    with campaign_tab:
        render_case_report(case_workspace)


    # ========================================================
    # RAW EVIDENCE
    # ========================================================

    with raw_tab:

        st.caption(
            "Complete machine-readable forensic output."
        )

        st.json(
            result,
            expanded=False
        )


else:

    st.markdown(
        """
        <div style="
            margin-top:3rem;
            text-align:center;
            color:#718491;
            padding:3rem;
        ">
            Upload an .EML file above to begin an investigation.
        </div>
        """,
        unsafe_allow_html=True
    )


if not result and case_workspace:
    render_case_report(case_workspace)
