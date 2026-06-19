import re
from collections import Counter

import pandas as pd

from error_database import lookup_error
from root_cause_engine import is_ignored_success_code


ERROR_CODE_PATTERN = re.compile(r"0x[0-9a-fA-F]{8}")
KEYWORD_PATTERN = re.compile(r"\b(error|failed|failure|fatal|exception|denied|timeout|timed out)\b", re.IGNORECASE)
TIME_PATTERN = re.compile(r"time=\"(?P<time>[^\"]+)\"")
DATE_PATTERN = re.compile(r"date=\"(?P<date>[^\"]+)\"")
COMPONENT_PATTERN = re.compile(r"component=\"(?P<component>[^\"]+)\"")


def read_uploaded_log(uploaded_file):
    """Read uploaded SCCM log content safely."""
    raw = uploaded_file.read()

    for encoding in ["utf-8", "utf-16", "latin-1"]:
        try:
            return raw.decode(encoding, errors="replace")
        except Exception:
            continue

    return raw.decode("utf-8", errors="replace")


def parse_log_lines(log_text):
    """Parse raw log text into structured rows."""
    rows = []

    for line_number, line in enumerate(log_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        all_codes = ERROR_CODE_PATTERN.findall(stripped)
        error_codes = [code for code in all_codes if not is_ignored_success_code(code)]
        success_codes = [code for code in all_codes if is_ignored_success_code(code)]
        has_keyword = bool(KEYWORD_PATTERN.search(stripped))

        time_match = TIME_PATTERN.search(stripped)
        date_match = DATE_PATTERN.search(stripped)
        component_match = COMPONENT_PATTERN.search(stripped)

        rows.append(
            {
                "Line": line_number,
                "Date": date_match.group("date") if date_match else "",
                "Time": time_match.group("time") if time_match else "",
                "Component": component_match.group("component") if component_match else "",
                "ErrorCodes": ", ".join(sorted(set(error_codes))),
                "IgnoredCodes": ", ".join(sorted(set(success_codes))),
                "HasErrorCode": bool(error_codes),
                "HasIgnoredCode": bool(success_codes),
                "HasKeyword": has_keyword,
                "Message": stripped,
            }
        )

    return pd.DataFrame(rows)


def find_error_events(parsed_df):
    """Return lines that look like errors or failures."""
    if parsed_df.empty:
        return pd.DataFrame()

    return parsed_df[
        (parsed_df["HasErrorCode"] == True) | (parsed_df["HasKeyword"] == True)
    ].copy()


def summarize_error_codes(parsed_df):
    """Summarize detected error codes and enrich them from the local database."""
    counter = Counter()

    for value in parsed_df.get("ErrorCodes", []):
        if not value:
            continue
        for code in [item.strip() for item in value.split(",") if item.strip()]:
            if is_ignored_success_code(code):
                continue
            counter[code] += 1

    rows = []
    for code, count in counter.most_common():
        details = lookup_error(code)
        rows.append(
            {
                "ErrorCode": code,
                "Count": count,
                "Severity": details["severity"],
                "Meaning": details["meaning"],
                "LikelyCause": details["likely_cause"],
                "RecommendedFix": details["recommended_fix"],
            }
        )

    return pd.DataFrame(rows)


def build_context_window(parsed_df, line_number, before=5, after=5):
    """Return log lines around a selected line."""
    if parsed_df.empty:
        return pd.DataFrame()

    return parsed_df[
        (parsed_df["Line"] >= line_number - before)
        & (parsed_df["Line"] <= line_number + after)
    ].copy()


def get_log_stats(parsed_df, error_events_df, error_summary_df):
    """Build top-level log stats."""
    ignored_code_count = 0
    if not parsed_df.empty and "IgnoredCodes" in parsed_df.columns:
        ignored_code_count = int((parsed_df["IgnoredCodes"] != "").sum())

    return {
        "total_lines": int(len(parsed_df)),
        "suspect_lines": int(len(error_events_df)),
        "unique_error_codes": int(len(error_summary_df)),
        "ignored_success_lines": ignored_code_count,
        "components": int(parsed_df["Component"].replace("", pd.NA).dropna().nunique()) if not parsed_df.empty else 0,
    }
