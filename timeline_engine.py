import pandas as pd


EVENT_PATTERNS = [
    {
        "label": "Task sequence started",
        "event_type": "Start",
        "keywords": ["task sequence", "started"],
        "severity": "Info",
    },
    {
        "label": "Package/content download started",
        "event_type": "Content",
        "keywords": ["download", "started"],
        "severity": "Info",
    },
    {
        "label": "Package/content download failed",
        "event_type": "Content",
        "keywords": ["download", "failed"],
        "severity": "High",
    },
    {
        "label": "Distribution point/location issue",
        "event_type": "Content Location",
        "keywords": ["location", "failed"],
        "severity": "High",
    },
    {
        "label": "Application install/enforcement event",
        "event_type": "Application",
        "keywords": ["appenforce"],
        "severity": "Medium",
    },
    {
        "label": "Application detection event",
        "event_type": "Application Detection",
        "keywords": ["detection"],
        "severity": "Medium",
    },
    {
        "label": "Access denied event",
        "event_type": "Permissions",
        "keywords": ["denied"],
        "severity": "High",
    },
    {
        "label": "Timeout event",
        "event_type": "Network",
        "keywords": ["timeout"],
        "severity": "Medium",
    },
    {
        "label": "Generic failure event",
        "event_type": "Failure",
        "keywords": ["failed"],
        "severity": "Medium",
    },
]


def _message_matches(message, keywords):
    lowered = str(message).lower()
    return all(keyword.lower() in lowered for keyword in keywords)


def _format_timestamp(row):
    date_value = str(row.get("Date", "")).strip()
    time_value = str(row.get("Time", "")).strip()

    if date_value and time_value:
        return f"{date_value} {time_value}"

    if time_value:
        return time_value

    if date_value:
        return date_value

    return ""


def classify_timeline_event(row):
    """Classify a parsed log row into a human-friendly timeline event."""
    message = str(row.get("Message", ""))
    error_codes = str(row.get("ErrorCodes", "")).strip()

    if error_codes:
        return {
            "Event": f"Error code detected: {error_codes}",
            "EventType": "Error Code",
            "Severity": "High",
        }

    for pattern in EVENT_PATTERNS:
        if _message_matches(message, pattern["keywords"]):
            return {
                "Event": pattern["label"],
                "EventType": pattern["event_type"],
                "Severity": pattern["severity"],
            }

    return None


def build_timeline(parsed_df):
    """Build a condensed event timeline from parsed SCCM log rows."""
    if parsed_df.empty:
        return pd.DataFrame()

    rows = []
    for _, row in parsed_df.iterrows():
        event = classify_timeline_event(row)
        if not event:
            continue

        rows.append(
            {
                "Line": int(row.get("Line", 0)),
                "Timestamp": _format_timestamp(row),
                "Component": row.get("Component", ""),
                "Severity": event["Severity"],
                "EventType": event["EventType"],
                "Event": event["Event"],
                "Message": row.get("Message", ""),
            }
        )

    return pd.DataFrame(rows)


def build_failure_chain(parsed_df):
    """Identify first actionable error and likely cascading failures."""
    if parsed_df.empty:
        return {
            "primary_failure": None,
            "resulting_failures": pd.DataFrame(),
            "summary": "No parsed log data available.",
        }

    actionable_errors = parsed_df[parsed_df.get("HasErrorCode", False) == True].copy()

    if actionable_errors.empty:
        keyword_failures = parsed_df[parsed_df.get("HasKeyword", False) == True].copy()
        if keyword_failures.empty:
            return {
                "primary_failure": None,
                "resulting_failures": pd.DataFrame(),
                "summary": "No actionable failure chain was detected.",
            }

        primary = keyword_failures.iloc[0]
        resulting = keyword_failures[keyword_failures["Line"] > primary["Line"]].head(10)
        return {
            "primary_failure": primary,
            "resulting_failures": resulting,
            "summary": f"Primary keyword-based failure appears near line {int(primary['Line'])}.",
        }

    primary = actionable_errors.iloc[0]
    resulting = actionable_errors[actionable_errors["Line"] > primary["Line"]].head(10)

    codes = str(primary.get("ErrorCodes", "")).strip() or "unknown error"
    summary = (
        f"Primary actionable error appears near line {int(primary['Line'])}: {codes}. "
        "Later errors may be cascading failures caused by this earlier issue."
    )

    return {
        "primary_failure": primary,
        "resulting_failures": resulting,
        "summary": summary,
    }
