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


APP_VERSION = "0.1"


def show_score_cards(stats):
    cols = st.columns(4)
    cols[0].metric("Total lines", stats["total_lines"])
    cols[1].metric("Suspect lines", stats["suspect_lines"])
    cols[2].metric("Unique error codes", stats["unique_error_codes"])
    cols[3].metric("Components", stats["components"])


def show_error_summary(error_summary_df):
    st.subheader("Detected error codes")

    if error_summary_df.empty:
        st.success("No hexadecimal error codes were detected. Suspicious, but in a nice way.")
        return

    st.dataframe(error_summary_df, width="stretch")

    csv = error_summary_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download Error Summary CSV",
        data=csv,
        file_name="smsts_detective_error_summary.csv",
        mime="text/csv",
    )


def show_suspect_lines(error_events_df):
    st.subheader("Suspect log lines")

    if error_events_df.empty:
        st.success("No suspect log lines found.")
        return

    search = st.text_input("Filter suspect lines", placeholder="error code, component, or text")
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
    )


def show_context_view(parsed_df, error_events_df):
    st.subheader("Context viewer")

    if error_events_df.empty:
        st.info("No suspect lines available for context view.")
        return

    line_options = error_events_df["Line"].astype(int).tolist()
    selected_line = st.selectbox("Select suspect line", line_options)
    context_range = st.slider("Context lines before/after", min_value=1, max_value=20, value=5)

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
    stats = get_log_stats(parsed_df, error_events_df, error_summary_df)

    show_score_cards(stats)

    if not error_summary_df.empty:
        top_error = error_summary_df.iloc[0]
        st.warning(
            f"Top detected error: {top_error['ErrorCode']} - {top_error['Meaning']} "
            f"({top_error['Count']} occurrence(s))."
        )
    elif not error_events_df.empty:
        st.warning("No known error codes were detected, but failure/error keywords were found.")
    else:
        st.success("No obvious error codes or failure keywords were detected.")

    overview_tab, errors_tab, suspect_tab, context_tab, components_tab, raw_tab = st.tabs(
        [
            "Overview",
            "Error Codes",
            "Suspect Lines",
            "Context Viewer",
            "Components",
            "Parsed Log",
        ]
    )

    with overview_tab:
        st.subheader("Analysis overview")
        st.write(
            "SMSTS Detective v0.1 scans for hexadecimal error codes, common failure keywords, "
            "SCCM component metadata, and nearby context lines."
        )
        show_error_summary(error_summary_df)

    with errors_tab:
        show_error_summary(error_summary_df)

    with suspect_tab:
        show_suspect_lines(error_events_df)

    with context_tab:
        show_context_view(parsed_df, error_events_df)

    with components_tab:
        show_component_summary(parsed_df)

    with raw_tab:
        show_raw_log(parsed_df)


if __name__ == "__main__":
    main()
