GENERIC_RULES = [
    {
        "finding": "Missing or unavailable content",
        "confidence": 80,
        "signals": ["0x80070002", "0x87d00607", "0x87d01106", "content", "download", "package"],
        "why": "The log contains content download or file-not-found signals, which commonly point to missing package/application content or DP availability issues.",
        "recommended_action": "Verify content distribution, redistribute the package/application, confirm DP content status, and check CAS.log/ContentTransferManager.log.",
    },
    {
        "finding": "Boundary group or distribution point selection issue",
        "confidence": 70,
        "signals": ["0x87d00607", "location", "boundary", "distribution point", "dp", "no locations"],
        "why": "The log suggests the client may not be locating a valid distribution point for the requested content.",
        "recommended_action": "Review boundary and boundary group assignment, site system references, DP fallback settings, and LocationServices.log.",
    },
    {
        "finding": "Permission or access failure",
        "confidence": 78,
        "signals": ["0x80070005", "access denied", "denied", "permission", "unauthorized"],
        "why": "Access denied or permission-related events were detected.",
        "recommended_action": "Check network access account, computer account access, NTFS/share permissions, IIS permissions, and package source permissions.",
    },
    {
        "finding": "Generic failure requiring context review",
        "confidence": 50,
        "signals": ["0x80004005", "failed"],
        "why": "A generic failure was detected. The first actionable failure before this event usually matters most.",
        "recommended_action": "Use the Failure Chain and Context Viewer tabs to find the first error before the generic failure.",
    },
]

SMSTS_RULES = [
    {
        "finding": "Task sequence content missing or unavailable",
        "confidence": 88,
        "signals": ["0x80070002", "0x87d00607", "0x87d01106", "content", "package", "download", "failed to resolve"],
        "why": "Task sequence failures with file-not-found or content signals usually indicate missing package content, unavailable DP content, or a bad source reference.",
        "recommended_action": "Identify the failed TS step, verify the referenced package/application/driver package, redistribute content, and confirm DP content status.",
    },
    {
        "finding": "Driver package or operating system image issue",
        "confidence": 82,
        "signals": ["driver", "apply driver", "0x80070002", "0x80004005", "image", "wim", "apply operating system"],
        "why": "Driver/image related text appears near task sequence failures, suggesting a driver package, boot image, or OS image content problem.",
        "recommended_action": "Validate driver package distribution, boot image drivers, OS image availability, and the failing Apply Driver Package or Apply Operating System step.",
    },
    {
        "finding": "Task sequence variable or command-line issue",
        "confidence": 72,
        "signals": ["variable", "command line", "invalid", "not found", "0x80070002", "failed to run command line"],
        "why": "The log includes task sequence variable or command-line failure signals.",
        "recommended_action": "Review the failing Run Command Line step, package association, working directory, referenced files, and required TS variables.",
    },
    {
        "finding": "Task sequence generic failure with earlier root cause",
        "confidence": 65,
        "signals": ["0x80004005", "task sequence", "failed", "execution failed"],
        "why": "0x80004005 is often the final visible failure after an earlier actionable error.",
        "recommended_action": "Use Failure Chain to review the first actionable error before 0x80004005, not just the final failure line.",
    },
]

CAS_RULES = [
    {
        "finding": "Client cannot access required content",
        "confidence": 88,
        "signals": ["0x87d00607", "0x87d01106", "content", "download", "cache", "failed"],
        "why": "CAS.log content download and cache signals commonly indicate content is unavailable, inaccessible, or cannot be staged locally.",
        "recommended_action": "Check client cache size, CAS.log, ContentTransferManager.log, DataTransferService.log, DP content status, and boundary group assignment.",
    },
    {
        "finding": "Distribution point selection problem",
        "confidence": 82,
        "signals": ["no locations", "location", "distribution point", "dp", "boundary", "0x87d00607"],
        "why": "The client appears unable to locate or use a valid content location.",
        "recommended_action": "Validate boundaries, boundary groups, DP assignments, fallback settings, and LocationServices.log.",
    },
]

APPENFORCE_RULES = [
    {
        "finding": "Application install command failure",
        "confidence": 82,
        "signals": ["appenforce", "process", "exit code", "installation failed", "failed", "0x80004005"],
        "why": "AppEnforce-style install execution signals were detected.",
        "recommended_action": "Review the install command, return codes, detection method, user/system context, and AppEnforce.log around the process exit line.",
    },
    {
        "finding": "Application detection method failure",
        "confidence": 86,
        "signals": ["0x87d00324", "detection", "application not detected", "appdiscovery", "not detected"],
        "why": "The application may have installed, but the detection method did not evaluate as installed.",
        "recommended_action": "Review detection method logic, MSI product code, registry/file detection paths, install behavior, and AppDiscovery.log.",
    },
]

WUA_RULES = [
    {
        "finding": "WSUS or Software Update Point availability issue",
        "confidence": 84,
        "signals": ["0x80244022", "0x80072ee2", "wsus", "sup", "wua", "server unavailable", "timeout", "timed out"],
        "why": "Software update logs contain WSUS/SUP or timeout signals.",
        "recommended_action": "Check WSUS app pool, IIS health, SUP configuration, WCM.log, WSUSCtrl.log, WUAHandler.log, and proxy/firewall behavior.",
    },
    {
        "finding": "Windows Update scan or policy issue",
        "confidence": 76,
        "signals": ["scan failed", "policy", "assignment", "updatesdeployment", "wuahandler", "0x87d00215"],
        "why": "The log suggests scan, policy, or deployment assignment issues around software updates.",
        "recommended_action": "Refresh machine policy, verify deployments, review WUAHandler.log, UpdatesDeployment.log, ScanAgent.log, and collection targeting.",
    },
]

CONTENTTRANSFER_RULES = [
    {
        "finding": "BITS or content transfer failure",
        "confidence": 84,
        "signals": ["contenttransfermanager", "bits", "download", "transfer", "failed", "0x87d01106", "0x80072ee2"],
        "why": "The log includes content transfer or BITS failure indicators.",
        "recommended_action": "Check BITS service health, client network path to DP, proxy/firewall rules, DataTransferService.log, and DP availability.",
    },
]

RULE_PACKS = {
    "Task Sequence / smsts.log": SMSTS_RULES,
    "Content Access / CAS.log": CAS_RULES,
    "Application Enforcement / AppEnforce.log": APPENFORCE_RULES,
    "Application Detection / AppDiscovery.log": APPENFORCE_RULES,
    "Software Updates / WUAHandler.log": WUA_RULES,
    "Software Updates Deployment / UpdatesDeployment.log": WUA_RULES,
    "Content Transfer / ContentTransferManager.log": CONTENTTRANSFER_RULES,
    "Unknown SCCM log type": GENERIC_RULES,
}


def get_rules_for_log_type(log_type):
    """Return SCCM-specific rules for the detected log type, with generic fallback rules included."""
    selected_rules = RULE_PACKS.get(log_type, GENERIC_RULES)

    if selected_rules is GENERIC_RULES:
        return GENERIC_RULES, "Generic"

    return selected_rules + GENERIC_RULES, log_type
