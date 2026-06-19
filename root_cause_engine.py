import pandas as pd

from rule_packs import get_rules_for_log_type


SUCCESS_CODES = {
    "0x00000000",
    "0x01000000",
}


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


def score_root_causes(parsed_df, error_summary_df, log_type="Unknown SCCM log type"):
    """Score likely root causes using SCCM-specific rule packs."""
    if parsed_df.empty:
        return pd.DataFrame()

    combined_text = " ".join(parsed_df["Message"].astype(str).tolist()).lower()
    detected_codes = set()

    if not error_summary_df.empty and "ErrorCode" in error_summary_df.columns:
        detected_codes = set(error_summary_df["ErrorCode"].astype(str).str.lower().tolist())

    rules, rule_pack_name = get_rules_for_log_type(log_type)

    rows = []
    for rule in rules:
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
                "RulePack": rule_pack_name,
                "Finding": rule["finding"],
                "Confidence": confidence,
                "MatchedSignals": ", ".join(matched_signals),
                "Why": rule["why"],
                "RecommendedAction": rule["recommended_action"],
            }
        )

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows).sort_values(by=["Confidence", "Finding"], ascending=[False, True])
