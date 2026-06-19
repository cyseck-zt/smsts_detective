KNOWLEDGE_BASE = {
    "0x80070002": {
        "title": "File not found",
        "plain_english": "SCCM tried to use a file, package, script, driver, or source path that was not available where the client expected it.",
        "common_sccm_causes": [
            "Package, application, driver package, or OS image content is missing from the distribution point.",
            "A task sequence step references a file that is not present in the selected package.",
            "A command line uses the wrong working directory or relative path.",
            "Content source was changed but not redistributed.",
            "The client selected a DP that does not have the required content.",
        ],
        "check_next": [
            "Review the Failure Chain tab for the first occurrence of 0x80070002.",
            "Use Context Viewer around the first failure line.",
            "Check Distribution Status for the referenced package/application/driver package.",
            "Review CAS.log and ContentTransferManager.log for content location/download issues.",
            "Verify the task sequence step package reference and command path.",
        ],
        "related_logs": ["smsts.log", "CAS.log", "ContentTransferManager.log", "DataTransferService.log"],
        "related_components": ["Task Sequence", "Content Access", "Distribution Point", "Driver Package"],
    },
    "0x80070005": {
        "title": "Access denied",
        "plain_english": "The client reached something but did not have permission to use it. SCCM, naturally, chooses to express this as a hex code instead of a useful sentence.",
        "common_sccm_causes": [
            "Computer account lacks access to package source or DP content.",
            "Network Access Account is missing, incorrect, locked out, or lacks permissions.",
            "NTFS or share permissions block the client.",
            "Task sequence step runs in a security context that cannot access the target resource.",
            "IIS or DP virtual directory permissions are unhealthy.",
        ],
        "check_next": [
            "Check the exact resource path near the access denied line.",
            "Validate Network Access Account configuration if used.",
            "Review package source share and NTFS permissions.",
            "Check IIS/DP health if the denied resource is DP-hosted content.",
            "Confirm whether the task sequence step runs as system or a specified account.",
        ],
        "related_logs": ["smsts.log", "CAS.log", "ContentTransferManager.log", "DataTransferService.log"],
        "related_components": ["Permissions", "Network Access Account", "Distribution Point", "Task Sequence"],
    },
    "0x80004005": {
        "title": "Unspecified error",
        "plain_english": "This is SCCM's favorite way of saying something failed without doing the basic courtesy of saying what. It is usually a secondary symptom, not the real root cause.",
        "common_sccm_causes": [
            "Earlier content download failure cascaded into a generic task sequence failure.",
            "Driver injection, OS image apply, or command-line step failed.",
            "Task sequence variable, script, or package reference is wrong.",
            "Access or network issue occurred earlier in the log.",
            "Application install returned a generic failure code.",
        ],
        "check_next": [
            "Do not stop at 0x80004005. Find the first actionable error before it.",
            "Use the Failure Chain tab to identify earlier failures.",
            "Review 20-50 lines before the generic failure.",
            "Identify the failed task sequence step or app install command.",
            "Check whether another code like 0x80070002 or 0x80070005 appears earlier.",
        ],
        "related_logs": ["smsts.log", "AppEnforce.log", "CAS.log"],
        "related_components": ["Task Sequence", "Application Enforcement", "Generic Failure"],
    },
    "0x87d00607": {
        "title": "Content not found or not available from DP",
        "plain_english": "The client could not find usable content from an assigned distribution point.",
        "common_sccm_causes": [
            "Boundary or boundary group does not assign the expected DP.",
            "Content is not distributed to the DP selected by the client.",
            "DP is unhealthy or unavailable.",
            "Fallback behavior is disabled or misconfigured.",
            "Client is on a network not covered by boundaries.",
        ],
        "check_next": [
            "Validate client IP/subnet against SCCM boundaries.",
            "Review boundary group DP assignments and fallback settings.",
            "Check Distribution Status for the content ID/package ID.",
            "Review LocationServices.log for location selection.",
            "Review CAS.log and ContentTransferManager.log for download behavior.",
        ],
        "related_logs": ["CAS.log", "ContentTransferManager.log", "LocationServices.log", "smsts.log"],
        "related_components": ["Boundary Groups", "Distribution Point", "Content Location"],
    },
    "0x87d00324": {
        "title": "Application detection failed",
        "plain_english": "The install may have run, but SCCM did not detect the application as installed afterward.",
        "common_sccm_causes": [
            "Detection method checks the wrong registry key, file path, MSI product code, or version.",
            "Application installs per-user but detection runs under system context.",
            "Install completed but returned before files/registry keys were fully created.",
            "32-bit vs 64-bit registry redirection issue.",
            "Detection rule expects a version newer/different than what was installed.",
        ],
        "check_next": [
            "Review AppDiscovery.log for detection evaluation details.",
            "Review AppEnforce.log for install command and exit code.",
            "Validate the detection method manually on an affected client.",
            "Check 32-bit vs 64-bit registry detection settings.",
            "Confirm the install actually creates the expected file/registry/MSI evidence.",
        ],
        "related_logs": ["AppDiscovery.log", "AppEnforce.log"],
        "related_components": ["Application Model", "Detection Method", "App Enforcement"],
    },
    "0x87d01106": {
        "title": "Content download failed",
        "plain_english": "The client found content but failed while downloading or staging it locally.",
        "common_sccm_causes": [
            "Client cache is too small or corrupt.",
            "BITS transfer failed or is unhealthy.",
            "Network interruption between client and DP.",
            "DP content is corrupt or incomplete.",
            "Firewall/proxy blocks content transfer.",
        ],
        "check_next": [
            "Check client cache size and clear cache only when appropriate.",
            "Review CAS.log, ContentTransferManager.log, and DataTransferService.log.",
            "Verify BITS service health.",
            "Validate DP content status and redistribute if needed.",
            "Test client connectivity to the DP.",
        ],
        "related_logs": ["CAS.log", "ContentTransferManager.log", "DataTransferService.log"],
        "related_components": ["Client Cache", "BITS", "Distribution Point"],
    },
    "0x80072ee2": {
        "title": "Operation timed out",
        "plain_english": "The client waited for a network or service response and gave up, which is rude but understandable.",
        "common_sccm_causes": [
            "WSUS/SUP timeout.",
            "Proxy or firewall interrupting traffic.",
            "Distribution point or management point is slow/unreachable.",
            "Network instability during download or scan.",
            "IIS app pool/service issue.",
        ],
        "check_next": [
            "Identify which component timed out from the log type and context.",
            "Check client network/proxy settings.",
            "Review IIS and app pool health on the server side.",
            "Check WUAHandler.log for update scan timeouts.",
            "Check DataTransferService.log for transfer timeouts.",
        ],
        "related_logs": ["WUAHandler.log", "DataTransferService.log", "ContentTransferManager.log", "LocationServices.log"],
        "related_components": ["Network", "WSUS/SUP", "BITS", "IIS"],
    },
    "0x80244022": {
        "title": "WSUS/SUP service unavailable",
        "plain_english": "The client could not get a valid response from WSUS or the Software Update Point.",
        "common_sccm_causes": [
            "WSUS app pool stopped or recycling repeatedly.",
            "IIS returning HTTP 503.",
            "SUP is unhealthy or unreachable.",
            "WSUS database or cleanup issue causing poor performance.",
            "Client proxy/firewall blocks WSUS traffic.",
        ],
        "check_next": [
            "Check WUAHandler.log on the client.",
            "Check WSUSCtrl.log and WCM.log on the site server.",
            "Review IIS app pool status for WSUSPool.",
            "Test WSUS URL reachability from the client.",
            "Check WSUS server CPU/memory and database health.",
        ],
        "related_logs": ["WUAHandler.log", "WindowsUpdate.log", "WSUSCtrl.log", "WCM.log"],
        "related_components": ["Software Update Point", "WSUS", "IIS"],
    },
}


def get_kb_entry(error_code):
    """Return a knowledge base entry for an error code."""
    return KNOWLEDGE_BASE.get(str(error_code).lower()) or KNOWLEDGE_BASE.get(str(error_code).upper()) or KNOWLEDGE_BASE.get(str(error_code))


def build_kb_dataframe(error_summary_df):
    """Build a display dataframe of KB entries for detected error codes."""
    rows = []

    if error_summary_df is None or error_summary_df.empty:
        return rows

    for _, row in error_summary_df.iterrows():
        code = str(row.get("ErrorCode", "")).strip()
        entry = get_kb_entry(code)
        if not entry:
            rows.append(
                {
                    "ErrorCode": code,
                    "Title": "No KB entry yet",
                    "PlainEnglish": "This code has not been added to the local knowledge base yet.",
                    "CommonCauses": "Add this if it appears often in your environment.",
                    "CheckNext": "Use the Context Viewer and Failure Chain tabs.",
                    "RelatedLogs": "Unknown",
                    "RelatedComponents": "Unknown",
                }
            )
            continue

        rows.append(
            {
                "ErrorCode": code,
                "Title": entry["title"],
                "PlainEnglish": entry["plain_english"],
                "CommonCauses": " | ".join(entry["common_sccm_causes"]),
                "CheckNext": " | ".join(entry["check_next"]),
                "RelatedLogs": ", ".join(entry["related_logs"]),
                "RelatedComponents": ", ".join(entry["related_components"]),
            }
        )

    return rows
