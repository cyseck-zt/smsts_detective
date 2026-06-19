ERROR_DATABASE = {
    "0x80070002": {
        "meaning": "File not found",
        "likely_cause": "Missing content, incorrect path, or referenced file unavailable.",
        "recommended_fix": "Verify package/application content exists, redistribute content to distribution points, and confirm paths referenced by the deployment are correct.",
        "severity": "High",
    },
    "0x80070005": {
        "meaning": "Access denied",
        "likely_cause": "Permission issue, blocked account access, or insufficient rights to content or share.",
        "recommended_fix": "Verify network access account, computer account permissions, share permissions, NTFS permissions, and task sequence account usage.",
        "severity": "High",
    },
    "0x80004005": {
        "meaning": "Unspecified error",
        "likely_cause": "Generic failure. Often appears during task sequence, driver, content, or command execution failures.",
        "recommended_fix": "Review the surrounding log lines to identify the failing step. Check content availability, command syntax, driver packages, and task sequence variables.",
        "severity": "High",
    },
    "0x87d00607": {
        "meaning": "Content not found or not available from distribution point",
        "likely_cause": "Boundary group issue, missing DP content, or client unable to locate content.",
        "recommended_fix": "Confirm boundary/boundary group assignment, redistribute content, validate DP health, and check LocationServices.log/CAS.log.",
        "severity": "High",
    },
    "0x87d00215": {
        "meaning": "Item not found or deployment policy unavailable",
        "likely_cause": "Client policy issue, expired deployment, or missing assignment/policy.",
        "recommended_fix": "Refresh machine policy, verify deployment targeting, confirm collection membership, and review PolicyAgent.log.",
        "severity": "Medium",
    },
    "0x87d00324": {
        "meaning": "Application detection method failed",
        "likely_cause": "Application installed but detection rule did not evaluate as expected.",
        "recommended_fix": "Review detection method logic, registry/file/MSI product code detection, and AppDiscovery.log/AppEnforce.log.",
        "severity": "Medium",
    },
    "0x87d01106": {
        "meaning": "Content download failed",
        "likely_cause": "Client failed to download content from DP or cache.",
        "recommended_fix": "Check CAS.log, ContentTransferManager.log, DataTransferService.log, BITS health, cache size, and DP content status.",
        "severity": "High",
    },
    "0x80072ee2": {
        "meaning": "Operation timed out",
        "likely_cause": "Network timeout, WSUS/SUP connectivity issue, proxy issue, or service unavailable.",
        "recommended_fix": "Check network connectivity, proxy settings, WSUS/SUP availability, IIS health, and client firewall/proxy behavior.",
        "severity": "Medium",
    },
    "0x80244022": {
        "meaning": "WSUS/SUP service unavailable",
        "likely_cause": "WSUS or software update point unavailable, overloaded, or returning HTTP 503.",
        "recommended_fix": "Check WSUS app pool, IIS, SUP health, WCM.log, WSUSCtrl.log, and client WUAHandler.log.",
        "severity": "High",
    },
}


def lookup_error(error_code):
    """Return known error information or a generic fallback."""
    normalized = str(error_code).lower()
    for known_code, details in ERROR_DATABASE.items():
        if known_code.lower() == normalized:
            return details

    return {
        "meaning": "Unknown error code",
        "likely_cause": "This error is not yet in the local SMSTS Detective knowledge base.",
        "recommended_fix": "Review the surrounding log lines and add this error to the knowledge base if it is recurring.",
        "severity": "Unknown",
    }
