import os
import tempfile
import streamlit as st

from backend.analyze import analyze_email


st.set_page_config(
    page_title="SpoofZero",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SpoofZero")

st.write(
    "AI-Powered Email Threat Detection, "
    "GeoLocation & Forensic Intelligence Platform"
)

st.divider()

st.subheader("📧 Upload Email for Analysis")

uploaded_file = st.file_uploader(
    "Upload a raw email file",
    type=["eml"]
)

if uploaded_file is not None:

    st.success(
        f"Email loaded: {uploaded_file.name}"
    )

    if st.button("🔍 Analyze Email"):

        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".eml"
            ) as temp_file:

                temp_file.write(uploaded_file.getvalue())
                temp_path = temp_file.name

            with st.spinner(
                "SpoofZero is investigating the email..."
            ):
                result = analyze_email(temp_path)

        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

        assessment = result["final_assessment"]
        ai = result["ai_analysis"]

        st.divider()

        st.subheader("🚨 Final Assessment")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Threat Score",
                f'{assessment["risk_score"]}/100'
            )

        with col2:
            st.metric(
                "Verdict",
                assessment["verdict"]
            )

        with col3:
            st.metric(
                "AI Phishing Probability",
                f'{ai["phishing_probability"]}%'
            )

        st.write(
            "**AI Verdict:**",
            ai["verdict"]
        )

        st.subheader("Why was this email flagged?")

        for reason in assessment["reasons"]:
            st.warning(reason)

        st.divider()

        st.subheader("🔐 Email Authentication")

        auth = result["authentication"]

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "SPF",
                auth["spf"].upper()
            )

        with col2:
            st.metric(
                "DKIM",
                auth["dkim"].upper()
            )

        with col3:
            st.metric(
                "DMARC",
                auth["dmarc"].upper()
            )

        st.divider()

        st.subheader("🌐 Indicators of Compromise")

        iocs = result["iocs"]

        st.write("**URLs**")
        st.write(iocs["urls"])

        st.write("**IP Addresses**")
        st.write(iocs["ips"])

        st.write("**Domains**")
        st.write(iocs["domains"])

        st.divider()

        st.subheader("📎 Attachment Forensics")

        attachment_data = result.get(
            "attachments",
            {}
        )

        attachment_count = attachment_data.get(
            "attachment_count",
            0
        )

        st.write(
            f"Attachments found: **{attachment_count}**"
        )

        attachments = attachment_data.get(
            "attachments",
            []
        )

        if attachments:

            for attachment in attachments:

                filename = attachment.get(
                    "filename",
                    "Unknown"
                )

                with st.expander(
                    f"📄 {filename}"
                ):

                    st.write(
                        "**Content Type:**",
                        attachment.get(
                            "content_type"
                        )
                    )

                    st.write(
                        "**Size:**",
                        f'{attachment.get("size_bytes", 0)} bytes'
                    )

                    st.code(
                        attachment.get(
                            "sha256",
                            ""
                        ),
                        language=None
                    )

                    st.caption(
                        "SHA-256 is a forensic fingerprint of the "
                        "attachment. A hash alone does not prove "
                        "that a file is malicious."
                    )

        else:

            st.info(
                "No attachments were found in this email."
            )

        st.divider()


        st.subheader("🦠 Attachment Reputation")

        attachment_rep = result.get(
            "attachment_reputation",
            []
        )

        if not attachment_rep:

            st.info(
                "No attachment hashes available for reputation checking."
            )

        else:

            for item in attachment_rep:

                filename = item.get(
                    "filename",
                    "Unknown attachment"
                )

                status = item.get(
                    "status",
                    "unknown"
                )

                with st.expander(
                    f"📄 {filename}"
                ):

                    st.write(
                        "**SHA-256:**"
                    )

                    st.code(
                        item.get(
                            "value",
                            ""
                        ),
                        language=None
                    )

                    if status == "success":

                        st.write(
                            "**VirusTotal Verdict:**",
                            item.get(
                                "verdict",
                                "UNKNOWN"
                            )
                        )

                        stats = item.get(
                            "analysis_stats",
                            {}
                        )

                        c1, c2, c3 = st.columns(3)

                        with c1:
                            st.metric(
                                "Malicious",
                                stats.get(
                                    "malicious",
                                    0
                                )
                            )

                        with c2:
                            st.metric(
                                "Suspicious",
                                stats.get(
                                    "suspicious",
                                    0
                                )
                            )

                        with c3:
                            st.metric(
                                "Harmless",
                                stats.get(
                                    "harmless",
                                    0
                                )
                            )

                        st.write(
                            "**Known File Type:**",
                            item.get(
                                "file_type"
                            )
                        )

                    elif status == "not_found":

                        st.info(
                            "This SHA-256 hash was not found "
                            "in VirusTotal. This means UNKNOWN, "
                            "not automatically safe."
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
                                "VirusTotal lookup failed"
                            )
                        )

        st.caption(
            "SpoofZero checks only the SHA-256 fingerprint. "
            "The attachment itself is not automatically uploaded."
        )

        st.divider()


        st.subheader("🧬 Threat Reputation")

        reputation = result.get(
            "reputation",
            {}
        )

        st.write("### 🌐 Domain Reputation")

        domain_results = reputation.get(
            "domains",
            []
        )

        for item in domain_results:

            domain = item.get(
                "value",
                "Unknown"
            )

            status = item.get(
                "status"
            )

            with st.expander(domain):

                if status == "skipped":

                    st.info(
                        item.get(
                            "reason",
                            "Lookup skipped"
                        )
                    )

                elif status == "error":

                    st.warning(
                        item.get(
                            "message",
                            "Lookup failed"
                        )
                    )

                else:

                    st.write(
                        "**Verdict:**",
                        item.get(
                            "verdict"
                        )
                    )

                    stats = item.get(
                        "analysis_stats",
                        {}
                    )

                    c1, c2, c3 = st.columns(3)

                    with c1:
                        st.metric(
                            "Malicious",
                            stats.get(
                                "malicious",
                                0
                            )
                        )

                    with c2:
                        st.metric(
                            "Suspicious",
                            stats.get(
                                "suspicious",
                                0
                            )
                        )

                    with c3:
                        st.metric(
                            "Harmless",
                            stats.get(
                                "harmless",
                                0
                            )
                        )

                    st.write(
                        "**VT Reputation:**",
                        item.get(
                            "vt_reputation"
                        )
                    )

                    st.write(
                        "**Registrar:**",
                        item.get(
                            "registrar"
                        )
                    )

        st.write("### 🖥️ IP Reputation")

        ip_results = reputation.get(
            "ips",
            []
        )

        for item in ip_results:

            ip = item.get(
                "value",
                "Unknown"
            )

            status = item.get(
                "status"
            )

            with st.expander(ip):

                if status == "skipped":

                    st.info(
                        item.get(
                            "reason",
                            "Lookup skipped"
                        )
                    )

                elif status == "error":

                    st.warning(
                        item.get(
                            "message",
                            "Lookup failed"
                        )
                    )

                else:

                    st.write(
                        "**Verdict:**",
                        item.get(
                            "verdict"
                        )
                    )

                    stats = item.get(
                        "analysis_stats",
                        {}
                    )

                    c1, c2, c3 = st.columns(3)

                    with c1:
                        st.metric(
                            "Malicious",
                            stats.get(
                                "malicious",
                                0
                            )
                        )

                    with c2:
                        st.metric(
                            "Suspicious",
                            stats.get(
                                "suspicious",
                                0
                            )
                        )

                    with c3:
                        st.metric(
                            "Harmless",
                            stats.get(
                                "harmless",
                                0
                            )
                        )

                    st.write(
                        "**Country:**",
                        item.get(
                            "country"
                        )
                    )

                    st.write(
                        "**ASN:**",
                        item.get(
                            "asn"
                        )
                    )

                    st.write(
                        "**Network Owner:**",
                        item.get(
                            "as_owner"
                        )
                    )

        st.caption(
            "VirusTotal detections are forensic "
            "signals, not proof by themselves."
        )

        st.divider()


        st.subheader("🧠 Domain Threat Intelligence")

        threat_data = result.get(
            "threat_intelligence",
            []
        )

        if threat_data:

            for domain_data in threat_data:

                domain = domain_data.get(
                    "domain",
                    "Unknown"
                )

                risk = domain_data.get(
                    "risk_score",
                    0
                )

                status = domain_data.get(
                    "status",
                    "unknown"
                )

                with st.expander(
                    f"{domain} — Risk {risk}/100"
                ):

                    if status == "reserved_demo":

                        st.info(
                            "Reserved demo/test domain. "
                            "Real reputation lookup skipped."
                        )

                    else:

                        st.write(
                            "**Risk Score:**",
                            f"{risk}/100"
                        )

                        indicators = domain_data.get(
                            "indicators",
                            []
                        )

                        if indicators:

                            st.write(
                                "**Forensic Indicators**"
                            )

                            for indicator in indicators:
                                st.warning(indicator)

                        dns_data = domain_data.get(
                            "dns",
                            {}
                        )

                        st.write(
                            "**A Records:**",
                            dns_data.get("A", [])
                        )

                        st.write(
                            "**MX Records:**",
                            dns_data.get("MX", [])
                        )

                        st.write(
                            "**Nameservers:**",
                            dns_data.get("NS", [])
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

        else:
            st.info(
                "No domains available for investigation."
            )

        st.divider()


        st.subheader("📡 Email Relay Trace")

        relay = result["relay_trace"]

        st.write(
            f'Number of relay hops: {relay["hop_count"]}'
        )

        origin_ip = relay.get("candidate_origin_ip")

        if origin_ip:
            st.success(
                f"Candidate Origin IP: {origin_ip}"
            )
        else:
            st.info(
                "No reliable public origin IP identified."
            )

        for hop in relay["hops"]:

            with st.expander(
                f'Hop {hop["hop_number"]} — '
                f'{hop["chain_status"]}'
            ):

                st.write(
                    "**From:**",
                    hop["from_host"]
                )

                st.write(
                    "**To:**",
                    hop["by_host"]
                )

                st.write(
                    "**Trust Score:**",
                    f'{hop["trust_score"]}/100'
                )

                st.write(
                    "**IP Information:**",
                    hop["ips"]
                )

        st.divider()

        st.subheader("🗺️ Origin Geo Intelligence")

        geo = result["geo_analysis"]

        if geo.get("status") == "success":

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    "Country",
                    geo.get("country") or "Unknown"
                )

            with col2:
                st.metric(
                    "Region",
                    geo.get("region") or "Unknown"
                )

            with col3:
                st.metric(
                    "City Estimate",
                    geo.get("city") or "Unknown"
                )

            col1, col2 = st.columns(2)

            with col1:
                st.write(
                    "**ISP:**",
                    geo.get("isp")
                )

                st.write(
                    "**Organization:**",
                    geo.get("organization")
                )

            with col2:
                st.write(
                    "**ASN:**",
                    geo.get("asn")
                )

                st.write(
                    "**Origin IP:**",
                    geo.get("ip")
                )

            latitude = geo.get("latitude")
            longitude = geo.get("longitude")

            if latitude is not None and longitude is not None:
                st.map(
                    [{
                        "lat": latitude,
                        "lon": longitude
                    }]
                )

            st.warning(
                geo.get("confidence_note")
            )

        else:
            st.info(
                geo.get(
                    "message",
                    "Geo intelligence unavailable."
                )
            )

        st.divider()

        with st.expander(
            "🧪 View Complete Forensic Data"
        ):
            st.json(result)
