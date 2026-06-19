import pandas as pd


SUCCESS_CODES = {
    "0x00000000",
    "0x01000000",
}

ROOT_CAUSE_RULES = [
    {
        "finding": "Missing or unavailable content",
        "confidence": 85,
        "signals": ["0x80070002", "0x87d00607", "0x87d01106", "content", "download", "package"],
        "why": "The log contains content download or file-not-found signals, which commonly point to missing package/application content or DP availability issues.",
        "recommended_action": "Verify content distribution, redistribute the package/application, confirm DP content status, and check CAS.log/ContentTransferManager.log.",
    },
    {
        "finding": "Boundary group or distribution point selection issue",
        "confidence": 75,
        "signals": ["0x87d00607", "location", "boundary", "distribution point", "dp", "no locations"],
        "why": "The log suggests the client may not be locating a valid distribution point for the requested content.",
        "recommended_action": "Review boundary and boundary group assignment, site system references, DP fallback settings, and LocationServices.log.",
    },
    {
        "finding": "Permission or access failure",
        "confidence": 80,
        "signals": ["0x80070005", "access denied", "denied", "permission", "unauthorized"],
        "why": "Access denied or permission-related events were detected.",
        "recommended_action": "Check network access account, computer account access, NTFS/share permissions, IIS permissions, and package source permissions.",
    },
    {
        "finding": "Application detection method failure",
        "confidence": 75,
        "signals": ["0x87d00324", "detection", "appdiscovery", "appenforce", "application not detected"],
        "why": "The log contains application detection signals, meaning the install may have completed but detection logic did not match.",
        "recommended_action": "Review detection rules, MSI product code, registry/file detection paths, AppDiscovery.log, and AppEnforce.log.",
    },
    {
        "finding": "Software update point or WSUS availability issue",
        "confidence": 75,
        "signals": ["0x80244022", "0x80072ee2", "wua", "wsus", "sup", "timeout", "timed out"],
        "why": "Windows Update Agent, WSUS, SUP, or timeout-related signals were detected.",
        "recommended_action": "Check WSUS app pool, IIS, SUP health, WCM.log, WSUSCtrl.log, WUAHandler.log, and proxy/firewall behavior.",
    },
    {
        "finding": "Generic task sequence failure requiring context review",
        "confidence": 55,
        "signals": ["0x80004005", "failed to run", "task sequence", "smsts", "failed"],
        "why": "A generic failure was detected. This code requires surrounding log context to identify the actual failing step.",
        "recommended_action": "Use the context viewer around the failure line. Look for the first failure before 0x80004005 and identify the failing task sequence step.",
    },
]


def normalize_code(code):
    return str(code).strip().lower()


def is_ignored_success_code(code):
    return normalize_code(code) in {item.lower() for item in SUCCESS_CODES}


def filter_success_codes_from_summary(error_summary_df):
    """Remove known success/status codes from error summary output."""
    if error_summary_df.empty or "ErrorCode" not in error_summary_df.columns:
        return error_summary_df

    return error_summary_df[
        ~error_summary_df["ErrorCode"].astype(str).str.lower().isin({code.lower() for code in SUCCESS_CODES})
    ].copy()


def score_root_causes(parsed_df, error_summary_df):
    """Score likely root causes using known error codes and keyword signals."""
    if parsed_df.empty:
        return pd.DataFrame()

    combined_text = " ".join(parsed_df["Message"].astype(str).tolist()).lower()
    detected_codes = set()

    if not error_summary_df.empty and "ErrorCode" in error_summary_df.columns:
        detected_codes = set(error_summary_df["ErrorCode"].astype(str).str.lower().tolist())

    rows = []
    for rule in ROOT_CAUSE_RULES:
        matched_signals = []

        for signal in rule["signals"]:
            signal_lower = signal.lower()
            if signal_lower.startswith("0x"):
                if signal_lower in detected_codes:
                    matched_signals.append(signal)
            elif signal_lower in combined_text:
                matched_signals.append(signal)

        if not matched_signals:
            continue

        signal_boost = min(len(matched_signals) * 5, 20)
        confidence = min(rule["confidence"] + signal_boost, 95)

        rows.append(
            {
                "Finding": rule["finding"],
                "Confidence": confidence,
                "MatchedSignals": ", ".join(matched_signals),
                "Why": rule["why"],
                "RecommendedAction": rule["recommended_action"],
            }
        )

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows).sort_values(by="Confidence", ascending=False)


def detect_log_type(parsed_df, filename=""):
    """Best-effort SCCM log type detection."""
    name = str(filename or "").lower()
    text_sample = " ".join(parsed_df["Message"].astype(str).head(100).tolist()).lower() if not parsed_df.empty else ""
    combined = f"{name} {text_sample}"

    if "smsts" in combined or "task sequence" in combined:
        return "Task Sequence / smsts.log"
    if "appenforce" in combined:
        return "Application Enforcement / AppEnforce.log"
    if "appdiscovery" in combined:
        return "Application Detection / AppDiscovery.log"
    if "contenttransfermanager" in combined or "content transfer" in combined:
        return "Content Transfer / ContentTransferManager.log"
    if "cas" in combined or "content access" in combined:
        return "Content Access / CAS.log"
    if "wuahandler" in combined or "windows update agent" in combined:
        return "Software Updates / WUAHandler.log"
    if "updatesdeployment" in combined:
        return "Software Updates Deployment / UpdatesDeployment.log"

    return "Unknown SCCM log type"
