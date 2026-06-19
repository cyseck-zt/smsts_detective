import pandas as pd
import streamlit as st

from log_parser import (
    build_context_window,
    find_error_events,
    get_log_stats,
    parse_log_lines,
    read_uploaded_log,
    summarize_error_codes,
)
from root_cause_engine import detect_log_type, score_root_causes
from timeline_engine import build_failure_chain, build_timeline


APP_VERSION = "0.4"


def show_score_cards(stats, log_type, rule_pack_name):
    cols = st.columns(6)
    cols[0].metric("Total lines", stats["total_lines"])
    cols[1].metric("Suspect lines", stats["suspect_lines"])
    cols[2].metric("Unique error codes", stats["unique_error_codes"])
    cols[3].metric("Ignored success lines", stats["ignored_success_lines"])
    cols[4].metric("Components", stats["components"])
    cols[5].metric("Rule pack", rule_pack_name)
    st.caption(f"Detected log type: {log_type}")


def show_summary_card(log_type, root_cause_df, failure_chain):
    st.subheader("Detective summary")

    top_finding = "No ranked finding"
    confidence = "N/A"
    recommended_action = "Review suspect lines and context viewer."
    rule_pack = "N/A"

    if not root_cause_df.empty:
        top = root_cause_df.iloc[0]
        top_finding = top.get("Finding", top_finding)
        confidence = f"{top.get('Confidence', 'N/A')}%"
        recommended_action = top.get("RecommendedAction", recommended_action)
        rule_pack = top.get("RulePack", rule_pack)

    primary = failure_chain.get("primary_failure")
    primary_text = "No primary failure detected"
    if primary is not None:
        primary_line = int(primary.get("Line", 0))
        primary_code = str(primary.get("ErrorCodes", "")).strip()
        primary_text = f"Line {primary_line}"
        if primary_code:
            primary_text += f" | {primary_code}"

    cols = st.columns(5)
    cols[0].metric("Log type", log_type)
    cols[1].metric("Rule pack", rule_pack)
    cols[2].metric("Likely cause", top_finding)
    cols[3].metric("Confidence", confidence)
    cols[4].metric("Primary failure", primary_text)

    st.info(recommended_action)


def show_root_cause_analysis(root_cause_df, key_suffix="root_cause"):
    st.subheader("Root cause ranking")

    if root_cause_df.empty:
        st.info("No root cause ranking could be generated yet. The log is either clean or the detective needs a better magnifying glass.")
        return

    top_finding = root_cause_df.iloc[0]
    st.warning(
        f"Top finding: {top_finding['Finding']} "
        f"({top_finding['Confidence']}% confidence)."
    )

    st.dataframe(root_cause_df, width="stretch")

    csv = root_cause_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Root Cause Ranking CSV",
        data=csv,
        file_name="smsts_detective_root_cause_ranking.csv",
        mime="text/csv",
        key=f"download_root_cause_{key_suffix}",
    )


def show_failure_chain(failure_chain):
    st.subheader("Failure chain")
    st.write(failure_chain.get("summary", "No failure chain summary available."))

    primary = failure_chain.get("primary_failure")
    if primary is None:
        st.info("No primary failure detected.")
        return

    st.write("### Primary failure")
    primary_df = pd.DataFrame([primary.to_dict() if hasattr(primary, "to_dict") else dict(primary)])
    st.dataframe(primary_df, width="stretch")

    resulting = failure_chain.get("resulting_failures", pd.DataFrame())
    st.write("### Possible cascading failures")
    if resulting is None or resulting.empty:
        st.info("No later cascading failures detected after the primary failure.")
    else:
        st.dataframe(resulting, width="stretch")
        st.download_button(
            "Download Failure Chain CSV",
            data=resulting.to_csv(index=False).encode("utf-8"),
            file_name="smsts_detective_failure_chain.csv",
            mime="text/csv",
            key="download_failure_chain",
        )


def show_timeline(timeline_df):
    st.subheader("Timeline")

    if timeline_df.empty:
        st.info("No timeline events were detected.")
        return

    severity_filter = st.multiselect(
        "Filter severity",
        sorted(timeline_df["Severity"].dropna().unique().tolist()),
        default=sorted(timeline_df["Severity"].dropna().unique().tolist()),
        key="timeline_severity_filter",
    )

    event_filter = st.multiselect(
        "Filter event type",
        sorted(timeline_df["EventType"].dropna().unique().tolist()),
        default=sorted(timeline_df["EventType"].dropna().unique().tolist()),
        key="timeline_event_filter",
    )

    filtered_df = timeline_df[
        timeline_df["Severity"].isin(severity_filter) & timeline_df["EventType"].isin(event_filter)
    ].copy()

    st.dataframe(filtered_df, width="stretch")

    st.download_button(
        "Download Timeline CSV",
        data=filtered_df.to_csv(index=False).encode("utf-8"),
        file_name="smsts_detective_timeline.csv",
        mime="text/csv",
        key="download_timeline",
    )


def show_error_summary(error_summary_df, key_suffix="error_summary"):
    st.subheader("Detected error codes")

    if error_summary_df.empty:
        st.success("No actionable hexadecimal error codes were detected. Known success/status codes were ignored.")
        return

    st.dataframe(error_summary_df, width="stretch")

    csv = error_summary_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Error Summary CSV",
        data=csv,
        file_name="smsts_detective_error_summary.csv",
        mime="text/csv",
        key=f"download_error_summary_{key_suffix}",
    )


def show_suspect_lines(error_events_df):
    st.subheader("Suspect log lines")

    if error_events_df.empty:
        st.success("No suspect log lines found.")
        return

    search = st.text_input("Filter suspect lines", placeholder="error code, component, or text", key="suspect_line_filter")
    filtered_df = error_events_df.copy()

    if search:
        mask = filtered_df.apply(
            lambda row: search.lower() in " ".join(row.astype(str)).lower(),
            axis=1,
        )
        filtered_df = filtered_df[mask]

    st.dataframe(filtered_df, width="stretch")

    csv = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Suspect Lines CSV",
        data=csv,
        file_name="smsts_detective_suspect_lines.csv",
        mime="text/csv",
        key="download_suspect_lines",
    )


def show_context_view(parsed_df, error_events_df):
    st.subheader("Context viewer")

    if error_events_df.empty:
        st.info("No suspect lines available for context view.")
        return

    line_options = error_events_df["Line"].astype(int).tolist()
    selected_line = st.selectbox("Select suspect line", line_options, key="context_selected_line")
    context_range = st.slider("Context lines before/after", min_value=1, max_value=20, value=5, key="context_range")

    context_df = build_context_window(
        parsed_df,
        selected_line,
        before=context_range,
        after=context_range,
    )

    st.dataframe(context_df, width="stretch")


def show_component_summary(parsed_df):
    st.subheader("Component summary")

    if parsed_df.empty or "Component" not in parsed_df.columns:
        st.info("No component data found.")
        return

    component_counts = (
        parsed_df[parsed_df["Component"] != ""]["Component"]
        .value_counts()
        .reset_index()
    )
    component_counts.columns = ["Component", "LineCount"]

    if component_counts.empty:
        st.info("No SCCM component metadata was detected in this log.")
        return

    st.bar_chart(component_counts.set_index("Component"))
    st.dataframe(component_counts, width="stretch")


def show_ignored_codes(parsed_df):
    st.subheader("Ignored success/status codes")

    if parsed_df.empty or "IgnoredCodes" not in parsed_df.columns:
        st.info("No ignored codes detected.")
        return

    ignored_df = parsed_df[parsed_df["IgnoredCodes"] != ""][["Line", "IgnoredCodes", "Message"]]

    if ignored_df.empty:
        st.info("No ignored success/status codes detected.")
        return

    st.write("These codes were detected but excluded from error ranking because they usually indicate success/status noise.")
    st.dataframe(ignored_df, width="stretch")


def show_raw_log(parsed_df):
    st.subheader("Parsed log")

    if parsed_df.empty:
        st.info("No parsed lines available.")
        return

    st.dataframe(parsed_df, width="stretch")


def main():
    st.set_page_config(page_title="SMSTS Detective", layout="wide")

    st.title("SMSTS Detective")
    st.caption(f"SCCM Log Analyzer | Version {APP_VERSION}")

    st.write(
        "Upload an SCCM client log such as smsts.log, AppEnforce.log, CAS.log, "
        "ContentTransferManager.log, WUAHandler.log, or UpdatesDeployment.log."
    )

    uploaded_file = st.file_uploader(
        "Upload SCCM log file",
        type=["log", "txt"],
    )

    if uploaded_file is None:
        st.info("Upload a log file to begin analysis. The detective refuses to investigate an empty crime scene.")
        return

    log_text = read_uploaded_log(uploaded_file)
    parsed_df = parse_log_lines(log_text)
    error_events_df = find_error_events(parsed_df)
    error_summary_df = summarize_error_codes(parsed_df)
    log_type = detect_log_type(parsed_df, uploaded_file.name)
    root_cause_df = score_root_causes(parsed_df, error_summary_df, log_type)
    timeline_df = build_timeline(parsed_df)
    failure_chain = build_failure_chain(parsed_df)
    stats = get_log_stats(parsed_df, error_events_df, error_summary_df)
    active_rule_pack = root_cause_df.iloc[0].get("RulePack", "Generic") if not root_cause_df.empty else "Generic"

    show_score_cards(stats, log_type, active_rule_pack)
    show_summary_card(log_type, root_cause_df, failure_chain)

    overview_tab, root_cause_tab, failure_chain_tab, timeline_tab, errors_tab, suspect_tab, context_tab, components_tab, ignored_tab, raw_tab = st.tabs(
        [
            "Overview",
            "Root Cause",
            "Failure Chain",
            "Timeline",
            "Error Codes",
            "Suspect Lines",
            "Context Viewer",
            "Components",
            "Ignored Codes",
            "Parsed Log",
        ]
    )

    with overview_tab:
        st.subheader("Analysis overview")
        st.write(
            "SMSTS Detective v0.4 adds SCCM-specific rule packs for task sequence, content, application, and software update logs."
        )
        show_root_cause_analysis(root_cause_df, key_suffix="overview")
        show_failure_chain(failure_chain)

    with root_cause_tab:
        show_root_cause_analysis(root_cause_df, key_suffix="tab")

    with failure_chain_tab:
        show_failure_chain(failure_chain)

    with timeline_tab:
        show_timeline(timeline_df)

    with errors_tab:
        show_error_summary(error_summary_df, key_suffix="tab")

    with suspect_tab:
        show_suspect_lines(error_events_df)

    with context_tab:
        show_context_view(parsed_df, error_events_df)

    with components_tab:
        show_component_summary(parsed_df)

    with ignored_tab:
        show_ignored_codes(parsed_df)

    with raw_tab:
        show_raw_log(parsed_df)


if __name__ == "__main__":
    main()
