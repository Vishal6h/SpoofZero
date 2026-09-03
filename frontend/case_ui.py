"""Case controls and correlation views alongside the original SpoofZero UI."""

import json
import sqlite3

import streamlit as st

from backend.analyzers.campaign_correlator import correlate_emails
from backend.case_analysis import MAX_BATCH_FILES, analyze_batch
from backend.case_store import CaseStore


STORE_ERRORS = (OSError, sqlite3.Error, ValueError)


def render_case_workspace():
    """Return the selected case and its saved analyses, or None."""
    with st.expander("Campaign / Case Correlation", expanded=False):
        st.caption(
            "Create a case to retain analyzed emails across sessions. Analysis snapshots "
            "are saved locally, including headers and indicators; raw EML files and "
            "attachment payloads are not retained."
        )
        try:
            store = CaseStore()
            with st.form("sz_create_case", clear_on_submit=True):
                name = st.text_input("New case name", max_chars=120)
                create = st.form_submit_button("Create case")
            if create:
                try:
                    st.session_state["sz_case_id"] = store.create_case(name)
                except ValueError as error:
                    st.warning(str(error))

            cases = store.list_cases()
            if not cases:
                st.info("Create a case, then add the current result or analyze a batch of emails.")
                return None
            by_id = {case["case_id"]: case for case in cases}
            if st.session_state.get("sz_case_id") not in by_id:
                st.session_state["sz_case_id"] = cases[0]["case_id"]
            case_id = st.selectbox(
                "Active case", list(by_id), key="sz_case_id",
                format_func=lambda key: f'{by_id[key]["name"]} · {key[:8]}',
            )
            case = by_id[case_id]

            current = st.session_state.get("spoofzero_result")
            if current:
                filename = st.session_state.get("spoofzero_filename", "email.eml")
                st.caption(f"Current dashboard result: {filename}")
                if st.button("Add current result to case", key="sz_save_current"):
                    try:
                        if store.add_analysis(case_id, filename, current):
                            st.success("Analysis saved to this case.")
                        else:
                            st.info("This exact email is already in the case.")
                    except STORE_ERRORS as error:
                        st.warning(str(error))

            files = st.file_uploader(
                "Add multiple EML files to this case", type=["eml"],
                accept_multiple_files=True, key="sz_batch_files",
                help="Up to 25 emails per batch, 10 MiB per email, and 200 unique emails per case.",
            )
            if st.button("Analyze batch", key="sz_analyze_batch", disabled=not files):
                if len(files) > MAX_BATCH_FILES:
                    st.warning(f"Select at most {MAX_BATCH_FILES} emails per batch.")
                else:
                    outcomes = []
                    progress = st.progress(0.0, text="Analyzing emails using the existing forensic pipeline...")
                    with st.spinner("Analyzing and saving each email. External intelligence lookups may take time..."):
                        batch = [(item.name, item.getvalue) for item in files]
                        for index, outcome in enumerate(analyze_batch(batch, case_id, store)):
                            outcomes.append({
                                "File": outcome["filename"], "Status": outcome["status"],
                                "Details": outcome.get("message", ""),
                            })
                            if outcome.get("analysis"):
                                st.session_state["spoofzero_result"] = outcome["analysis"]
                                st.session_state["spoofzero_filename"] = outcome["filename"]
                            progress.progress((index + 1) / len(files))
                    st.dataframe(outcomes, hide_index=True, width="stretch")
                    st.caption("Duplicate raw EML files are counted once per case and skip repeat lookups.")

            records = store.list_analyses(case_id)
            st.caption(f"{len(records)} unique analyzed emails in this case.")
            if records:
                records_by_id = {record["email_id"]: record for record in records}
                choice = st.selectbox(
                    "Saved email", list(records_by_id), key=f"sz_saved_email_{case_id}",
                    format_func=lambda key: f'{records_by_id[key]["filename"]} · {key[:8]}',
                )
                if st.button("Open email in dashboard", key="sz_open_email"):
                    record = records_by_id[choice]
                    st.session_state["spoofzero_result"] = record["analysis"]
                    st.session_state["spoofzero_filename"] = record["filename"]
            return {"case": case, "records": records}
        except STORE_ERRORS as error:
            st.warning(f"Case storage is unavailable: {error}")
            return None


def render_case_report(workspace):
    st.subheader("Campaign / Case Correlation")
    if not workspace:
        st.info("Open Campaign / Case Correlation above to create or select a case.")
        return
    case, records = workspace["case"], workspace["records"]
    st.write("**Case:**", case["name"])
    st.caption(
        "Links describe shared evidence, not maliciousness or attribution. Candidate groups "
        "can include indirect connections; inspect the direct links before drawing conclusions."
    )
    if not records:
        st.info("Add analyzed emails to this case to begin correlating evidence.")
        return
    minimum_score = st.slider(
        "Minimum link score for candidate groups", min_value=40, max_value=90,
        value=50, step=5, key="sz_minimum_link_score",
        help="This is a heuristic relationship score, not a threat score or probability.",
    )
    report = correlate_emails(records, minimum_score)
    by_id = {record["email_id"]: record for record in records}

    def label(email_id):
        return f'{by_id[email_id]["filename"]} · {email_id[:8]}'

    c1, c2, c3 = st.columns(3)
    c1.metric("Case emails", len(records))
    c2.metric("Candidate groups", len(report["campaigns"]))
    c3.metric("Shared indicators", len(report["shared_indicators"]))

    inventory = []
    for record in records:
        analysis = record["analysis"]
        email = analysis.get("email") or {}
        assessment = analysis.get("final_assessment") or {}
        inventory.append({
            "Email": label(record["email_id"]), "Subject": email.get("subject"),
            "From": email.get("from"), "Email date": email.get("date"),
            "Threat score": assessment.get("risk_score"), "Verdict": assessment.get("verdict"),
            "Saved at (UTC)": record["analyzed_at"],
        })
    st.dataframe(inventory, hide_index=True, width="stretch")
    if len(records) < 2:
        st.info("Add at least one more distinct email to find shared evidence.")

    for campaign in report["campaigns"]:
        with st.expander(f'{campaign["campaign_id"]} · {len(campaign["email_ids"])} emails', expanded=True):
            st.dataframe({"Member email": [label(key) for key in campaign["email_ids"]]}, hide_index=True)
            st.caption(
                f'{campaign["link_count"]} qualifying direct links; strongest link '
                f'{campaign["strongest_link_score"]}/100. Membership may be transitive.'
            )
    if len(records) >= 2 and not report["campaigns"]:
        st.info("No candidate groups meet this threshold. Shared evidence is still shown below.")

    st.write("**Direct email relationships**")
    show_weak = st.checkbox("Include weak and infrastructure-only relationships", value=True, key="sz_show_weak")
    pairs = [pair for pair in report["pairs"] if show_weak or pair["linked"]]
    if pairs:
        rows = [{
            "Email A": label(pair["left_id"]), "Email B": label(pair["right_id"]),
            "Link score": pair["score"], "Qualifies": pair["linked"],
            "Shared evidence": len(pair["evidence"]),
        } for pair in pairs]
        st.dataframe(rows, hide_index=True, width="stretch")
        # Select one pair rather than rendering potentially thousands of expanders.
        pair_keys = [(pair["left_id"], pair["right_id"]) for pair in pairs]
        pair_by_key = dict(zip(pair_keys, pairs))
        choice = st.selectbox(
            "Inspect a direct relationship", pair_keys,
            format_func=lambda key: f"{label(key[0])} ↔ {label(key[1])}",
            key=f"sz_pair_{case['case_id']}",
        )
        pair = pair_by_key[choice]
        st.dataframe([{
            "Type": item["kind"], "Shared value": item["value"],
            "Strength": item["weight"], "Evidence family": item["family"],
            "Source in A": "; ".join(item["left_sources"]),
            "Source in B": "; ".join(item["right_sources"]),
        } for item in pair["evidence"]], hide_index=True, width="stretch")
        st.caption("Only the strongest match in each evidence family contributes to the link score.")
    else:
        st.info("No direct relationships match the current view.")

    with st.expander("All shared indicators"):
        if report["shared_indicators"]:
            st.dataframe([{
                "Type": item["kind"], "Value": item["value"],
                "Email count": len(item["email_ids"]),
                "Emails": "; ".join(label(key) for key in item["email_ids"]),
            } for item in report["shared_indicators"]], hide_index=True, width="stretch")
        else:
            st.info("No normalized indicators are shared between distinct emails.")
    with st.expander("How correlation works"):
        st.write(
            "Non-empty attachment SHA-256: 60. Exact normalized URL: 50 "
            "(known shared providers: 10). Exact sender mailbox: 30. Domain: 10. "
            "Public IP: 10–20 by evidence source. Relay/MX/nameserver: 3. Network: 2. ASN: 1. "
            "Scores sum the maximum for each family: attachment, content, identity, infrastructure. "
            "Common provider domains, non-public IPs, and empty attachment hashes provide context only. "
            "Infrastructure alone cannot form a candidate group."
        )
        st.caption(
            "Sender headers and relay evidence may be spoofed. Domains are matched exactly; "
            "URLs preserve path, query, and fragment. Enrichment uses stored snapshots. "
            "No additional network lookups are made during correlation."
        )
    export = {"schema_version": 1, "case": {**case, "email_count": len(records)},
              "analyses": records, "correlation": report}
    st.download_button(
        "Export case evidence (JSON)", json.dumps(export, indent=2, ensure_ascii=False),
        file_name=f'spoofzero-case-{case["case_id"][:8]}.json', mime="application/json",
        key="sz_export_case",
    )
