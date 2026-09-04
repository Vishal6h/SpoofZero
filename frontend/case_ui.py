"""Searchable cases, analysis history, comparison, correlation, and reports."""

import sqlite3

import streamlit as st

from backend.analyzers.campaign_correlator import correlate_emails
from backend.case_analysis import MAX_BATCH_FILES, analyze_batch
from backend.case_reporting import (
    build_forensic_report, compare_analyses, report_html, report_json,
    sanitize_export_filename,
)
from backend.case_store import CaseStore
from backend.fusion_policy import snapshot_policy_version


STORE_ERRORS = (OSError, sqlite3.Error, ValueError)


def _record_label(record):
    suffix = "latest" if record.get("is_latest") else "historical"
    policy = snapshot_policy_version(
        (record.get("analysis") or {}).get("final_assessment") or {})
    return (
        f'{record.get("filename", "email.eml")} | analysis #{record.get("version", 1)} '
        f'| {policy} | {suffix}'
    )


def render_case_workspace():
    """Return selected case, latest records, and immutable history."""
    with st.expander("Campaign / Case Correlation", expanded=False):
        st.caption(
            "Analyze Email -> Save to Case -> Timeline / Evidence -> Compare / "
            "Correlate -> Export Report. Cases are local; raw EML files and "
            "attachment payloads are not retained."
        )
        try:
            store = CaseStore()
            with st.form("sz_create_case", clear_on_submit=True):
                name = st.text_input("New case name", max_chars=120)
                description = st.text_area("Optional case description", max_chars=1000)
                create = st.form_submit_button("Create case")
            if create:
                try:
                    st.session_state["sz_case_id"] = store.create_case(name, description)
                    st.success("Case created.")
                except ValueError as error:
                    st.warning(str(error))

            with st.expander("Search and filter cases"):
                query = st.text_input("Search case name, description, subject, or sender",
                                      key="sz_case_search")
                sender = st.text_input("Filter by sender or domain", key="sz_case_sender")
                f1, f2 = st.columns(2)
                verdict = f1.selectbox(
                    "Verdict / risk level",
                    ["Any", "LIKELY SAFE", "INCONCLUSIVE", "REVIEW REQUIRED",
                     "LOW RISK", "SUSPICIOUS", "HIGH RISK", "CRITICAL"],
                    key="sz_case_verdict",
                )
                relationship = f2.selectbox(
                    "Campaign relationship", ["Any", "Has candidate group", "No candidate group"],
                    key="sz_case_campaign",
                )
                d1, d2 = st.columns(2)
                date_from = d1.date_input("Analysis date from (UTC)", value=None,
                                          key="sz_case_date_from")
                date_to = d2.date_input("Analysis date to (UTC)", value=None,
                                        key="sz_case_date_to")
                sort = st.selectbox(
                    "Sort cases",
                    ["Recently updated", "Newest", "Oldest", "Highest risk"],
                    key="sz_case_sort",
                )
                include_archived = st.checkbox("Include archived cases",
                                               key="sz_include_archived")
            campaign_filter = {
                "Any": None, "Has candidate group": True, "No candidate group": False,
            }[relationship]
            cases = store.list_cases(
                query=query, sender=sender, verdict=None if verdict == "Any" else verdict,
                date_from=date_from, date_to=date_to, campaign=campaign_filter,
                sort={
                    "Recently updated": "recently_updated", "Newest": "newest",
                    "Oldest": "oldest", "Highest risk": "highest_risk",
                }[sort],
                include_archived=include_archived,
            )
            if not cases:
                st.info("No cases match this view. Adjust the filters or create a case.")
                return None
            by_id = {case["case_id"]: case for case in cases}
            if st.session_state.get("sz_case_id") not in by_id:
                st.session_state["sz_case_id"] = cases[0]["case_id"]
            case_id = st.selectbox(
                "Active case", list(by_id), key="sz_case_id",
                format_func=lambda key: (
                    f'{by_id[key]["name"]} | {key[:8]}'
                    f'{" | archived" if by_id[key]["archived"] else ""}'
                ),
            )
            case = by_id[case_id]
            st.caption(
                f'Created {case["created_at"]} | Updated {case["updated_at"]} | '
                f'{case["email_count"]} emails | {case["analysis_count"]} analyses'
            )
            if case.get("description"):
                st.write(case["description"])

            with st.expander("Case details and status"):
                with st.form(f"sz_edit_case_{case_id}"):
                    revised_name = st.text_input("Case name", value=case["name"],
                                                 max_chars=120)
                    revised_description = st.text_area(
                        "Case description", value=case.get("description", ""),
                        max_chars=1000,
                    )
                    save_details = st.form_submit_button("Save case details")
                if save_details:
                    store.rename_case(case_id, revised_name, revised_description)
                    case = store.get_case(case_id)
                    st.success("Case details updated.")
                archived = bool(case.get("archived"))
                if st.button("Restore case" if archived else "Archive case",
                             key=f"sz_archive_{case_id}"):
                    store.archive_case(case_id, not archived)
                    case = store.get_case(case_id)
                    st.info("Case restored." if archived else
                            "Case archived. Its evidence was not deleted.")

            current = st.session_state.get("spoofzero_result")
            if current and not case.get("archived"):
                filename = st.session_state.get("spoofzero_filename", "email.eml")
                st.caption(f"Current dashboard result: {filename}")
                save_version = st.checkbox(
                    "Save a new analysis version when this raw email already exists",
                    key=f"sz_save_version_{case_id}",
                    help="Use this only after intentionally running Analyze again.",
                )
                if st.button("Add current result to case", key="sz_save_current"):
                    try:
                        email_id = (current.get("email") or {}).get("sha256") or ""
                        previous = store.get_analysis(case_id, email_id) if email_id else None
                        inserted = store.add_analysis(
                            case_id, filename, current,
                            allow_reanalysis=save_version,
                            analysis_id=st.session_state.get("spoofzero_analysis_id"),
                            analyzed_at=st.session_state.get("spoofzero_analyzed_at"),
                        )
                        if inserted and previous:
                            st.success("Re-analysis appended as a new immutable version.")
                        elif inserted:
                            st.success("Analysis saved to this case.")
                        elif previous and previous["analysis"] != current:
                            st.info(
                                "This email already has a saved historical snapshot. Enable the explicit new-version "
                                "option after re-running Analyze to retain this result."
                            )
                        else:
                            st.info("This analysis is already saved in the case.")
                    except STORE_ERRORS as error:
                        st.warning(str(error))

            files = st.file_uploader(
                "Add multiple EML files to this case", type=["eml"],
                accept_multiple_files=True, key="sz_batch_files",
                help="Up to 25 emails per batch, 10 MiB per email, and 200 unique emails per case.",
                disabled=bool(case.get("archived")),
            )
            batch_reanalysis = st.checkbox(
                "Explicitly re-analyze existing raw emails in this batch",
                key=f"sz_batch_reanalyze_{case_id}", disabled=bool(case.get("archived")),
            )
            if st.button("Analyze batch", key="sz_analyze_batch",
                         disabled=not files or bool(case.get("archived"))):
                if len(files) > MAX_BATCH_FILES:
                    st.warning(f"Select at most {MAX_BATCH_FILES} emails per batch.")
                else:
                    outcomes = []
                    progress = st.progress(0.0, text="Analyzing emails...")
                    batch = [(item.name, item.getvalue) for item in files]
                    for index, outcome in enumerate(analyze_batch(
                            batch, case_id, store, allow_reanalysis=batch_reanalysis)):
                        outcomes.append({
                            "File": outcome["filename"], "Status": outcome["status"],
                            "Details": outcome.get("message", ""),
                        })
                        if outcome.get("analysis"):
                            st.session_state["spoofzero_result"] = outcome["analysis"]
                            st.session_state["spoofzero_filename"] = outcome["filename"]
                            st.session_state["spoofzero_analysis_id"] = outcome.get("analysis_id")
                            st.session_state["spoofzero_result_source"] = (
                                "saved_snapshot" if outcome["status"] == "duplicate"
                                else "fresh_analysis"
                            )
                        progress.progress((index + 1) / len(files))
                    st.dataframe(outcomes, hide_index=True, width="stretch")
                    st.caption(
                        "Duplicates skip lookups by default. Explicit re-analysis appends "
                        "one version per distinct raw payload in this batch."
                    )

            records = store.list_analyses(case_id)
            history = store.list_analysis_history(case_id)
            st.caption(
                f"{len(records)} unique emails and {len(history)} preserved analyses in this case."
            )
            if history:
                timeline = [{
                    "Email": item["filename"],
                    "Analysis": f'#{item["version"]}',
                    "State": "Latest" if item["is_latest"] else "Historical",
                    "Recorded at (UTC)": item["analyzed_at"],
                    "Risk": (item["analysis"].get("final_assessment") or {}).get("risk_score"),
                    "Verdict": (item["analysis"].get("final_assessment") or {}).get("verdict"),
                    "Fusion policy": snapshot_policy_version(
                        (item["analysis"].get("final_assessment") or {})),
                } for item in reversed(history)]
                st.dataframe(timeline, hide_index=True, width="stretch")

                choices = {item["analysis_id"]: item for item in history}
                choice = st.selectbox(
                    "Saved analysis", list(choices), key=f"sz_saved_analysis_{case_id}",
                    format_func=lambda key: _record_label(choices[key]),
                )
                if st.button("Open analysis in dashboard", key="sz_open_email"):
                    item = choices[choice]
                    st.session_state["spoofzero_result"] = item["analysis"]
                    st.session_state["spoofzero_filename"] = item["filename"]
                    st.session_state["spoofzero_analysis_id"] = item["analysis_id"]
                    st.session_state["spoofzero_analyzed_at"] = item["analyzed_at"]
                    st.session_state["spoofzero_result_source"] = "saved_snapshot"
            return {"case": case, "records": records, "history": history}
        except STORE_ERRORS as error:
            st.warning(f"Case storage is unavailable: {error}")
            return None


def render_case_report(workspace):
    st.subheader("Campaign / Case Investigation")
    if not workspace:
        st.info("Open Campaign / Case Correlation above to create or select a case.")
        return
    case, records = workspace["case"], workspace["records"]
    history = workspace.get("history", records)
    st.write("**Case:**", case["name"])
    st.caption(
        "Links describe shared evidence, not maliciousness, attacker identity, or "
        "authorship. Candidate groups may contain indirect connections."
    )
    if not records:
        st.info("Add analyzed emails to this case to begin investigating.")
        return

    minimum_score = st.slider(
        "Minimum link score for candidate groups", min_value=40, max_value=90,
        value=50, step=5, key="sz_minimum_link_score",
        help="A heuristic relationship score, not a threat score or probability.",
    )
    correlation = correlate_emails(records, minimum_score)
    by_id = {record["email_id"]: record for record in records}

    def label(email_id):
        return f'{by_id[email_id]["filename"]} | {email_id[:8]}'

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Case emails", len(records))
    c2.metric("Analysis versions", len(history))
    c3.metric("Candidate groups", len(correlation["campaigns"]))
    c4.metric("Shared indicators", len(correlation["shared_indicators"]))

    inventory = []
    for record in records:
        analysis = record["analysis"]
        email = analysis.get("email") or {}
        assessment = analysis.get("final_assessment") or {}
        inventory.append({
            "Email": label(record["email_id"]), "Subject": email.get("subject"),
            "From": email.get("from"), "Email date": email.get("date"),
            "Forensic risk score": assessment.get("risk_score"),
            "Fusion policy": snapshot_policy_version(assessment),
            "Verdict": assessment.get("verdict"),
            "Latest analysis (UTC)": record["analyzed_at"],
        })
    st.dataframe(inventory, hide_index=True, width="stretch")
    st.caption(
        "Historical scores retain their original policy and are never recalculated. "
        "Correlation uses only the latest saved version of each raw email."
    )

    if len(history) >= 2:
        st.markdown("#### Compare saved analyses")
        choices = {item["analysis_id"]: item for item in history}
        ids = list(choices)
        left_col, right_col = st.columns(2)
        left_id = left_col.selectbox(
            "Analysis A", ids, key=f"sz_compare_left_{case['case_id']}",
            format_func=lambda key: _record_label(choices[key]),
        )
        right_id = right_col.selectbox(
            "Analysis B", ids, index=1, key=f"sz_compare_right_{case['case_id']}",
            format_func=lambda key: _record_label(choices[key]),
        )
        comparison = compare_analyses(choices[left_id], choices[right_id])
        if comparison["changes"]:
            st.dataframe(comparison["changes"], hide_index=True, width="stretch")
        else:
            st.info("No differences were found in the compared forensic fields.")
        shared_rows = [
            {"Type": kind, "Shared indicator": value}
            for kind, values in comparison["shared_indicators"].items()
            for value in values
        ]
        if shared_rows:
            st.dataframe(shared_rows, hide_index=True, width="stretch")
        st.caption(comparison["note"])

    for campaign in correlation["campaigns"]:
        with st.expander(
            f'{campaign["campaign_id"]} | {len(campaign["email_ids"])} emails',
            expanded=True,
        ):
            st.dataframe(
                {"Member email": [label(key) for key in campaign["email_ids"]]},
                hide_index=True,
            )
            st.caption(
                f'{campaign["link_count"]} qualifying direct links; strongest link '
                f'{campaign["strongest_link_score"]}/100. Membership may be transitive.'
            )
    if len(records) >= 2 and not correlation["campaigns"]:
        st.info("No candidate groups meet this threshold.")

    st.write("**Direct email relationships**")
    show_weak = st.checkbox(
        "Include weak and infrastructure-only relationships", value=True,
        key="sz_show_weak",
    )
    pairs = [pair for pair in correlation["pairs"] if show_weak or pair["linked"]]
    if pairs:
        st.dataframe([{
            "Email A": label(pair["left_id"]), "Email B": label(pair["right_id"]),
            "Link score": pair["score"], "Qualifies": pair["linked"],
            "Shared evidence": len(pair["evidence"]),
        } for pair in pairs], hide_index=True, width="stretch")
        pair_keys = [(pair["left_id"], pair["right_id"]) for pair in pairs]
        pair_by_key = dict(zip(pair_keys, pairs))
        choice = st.selectbox(
            "Inspect a direct relationship", pair_keys,
            format_func=lambda key: f"{label(key[0])} <-> {label(key[1])}",
            key=f"sz_pair_{case['case_id']}",
        )
        pair = pair_by_key[choice]
        st.dataframe([{
            "Type": item["kind"], "Shared value": item["value"],
            "Strength": item["weight"], "Evidence family": item["family"],
            "Source in A": "; ".join(item["left_sources"]),
            "Source in B": "; ".join(item["right_sources"]),
        } for item in pair["evidence"]], hide_index=True, width="stretch")
    else:
        st.info("No direct relationships match the current view.")

    with st.expander("All shared indicators"):
        if correlation["shared_indicators"]:
            st.dataframe([{
                "Type": item["kind"], "Value": item["value"],
                "Email count": len(item["email_ids"]),
                "Emails": "; ".join(label(key) for key in item["email_ids"]),
            } for item in correlation["shared_indicators"]],
                         hide_index=True, width="stretch")
        else:
            st.info("No normalized indicators are shared between distinct emails.")

    with st.expander("Forensic reports", expanded=True):
        st.caption(
            "Reports summarize evidence by default. Full raw emails and attachment "
            "payloads are never added automatically."
        )
        include_body = st.checkbox(
            "Explicitly include investigator-supplied readable body text",
            key=f"sz_report_body_{case['case_id']}",
        )
        sensitive_bodies = {}
        if include_body:
            target = st.selectbox(
                "Body belongs to analysis", [item["analysis_id"] for item in history],
                format_func=lambda key: _record_label(
                    next(item for item in history if item["analysis_id"] == key)),
                key=f"sz_report_body_target_{case['case_id']}",
            )
            body = st.text_area(
                "Readable body text to include", height=120,
                help="This text is used only in the generated download and is not stored.",
                key=f"sz_report_body_text_{case['case_id']}",
            )
            if body:
                sensitive_bodies[target] = body
        report = build_forensic_report(
            case, history, correlation,
            include_sensitive=include_body, sensitive_bodies=sensitive_bodies,
        )
        r1, r2 = st.columns(2)
        r1.download_button(
            "Download forensic report (JSON)", report_json(report),
            file_name=sanitize_export_filename(case["name"], case["case_id"], "json"),
            mime="application/json", key="sz_export_case_json",
        )
        r2.download_button(
            "Download printable forensic report (HTML)", report_html(report),
            file_name=sanitize_export_filename(case["name"], case["case_id"], "html"),
            mime="text/html", key="sz_export_case_html",
        )
        st.caption(
            f'Report SHA-256: {report["integrity"]["sha256"]}. This is a content '
            "checksum, not a legal digital signature."
        )
