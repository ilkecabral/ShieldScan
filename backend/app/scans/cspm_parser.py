import logging

logger = logging.getLogger("shieldscan")

def process_prowler_findings(raw_prowler_report: list) -> list:
    """
    Core CSPM Data Normalization Layer.
    Parses raw Prowler compliance JSON lists into a uniform internal schema 
    for storage in DynamoDB, focusing strictly on cloud misconfigurations.
    """
    clean_cspm_findings = []
    
    if not raw_prowler_report:
        logger.warning("Empty Prowler report received.")
        return clean_cspm_findings

    for item in raw_prowler_report:
        # We only want to alert on actual failures or misconfigurations
        if item.get("Status") == "FAIL":
            finding = {
                "finding_id": item.get("FindingUniqueId", "UNKNOWN_ID"),
                "cloud_provider": "AWS",
                "service_name": item.get("ServiceName", "Unknown Service"),
                "check_id": item.get("CheckID", "UNKNOWN_CHECK"),
                "check_title": item.get("CheckTitle", "No Title Provided"),
                "region": item.get("Region", "eu-west-3"),
                "resource_id": item.get("ResourceID", "Unknown Resource"),
                "severity": item.get("Severity", "LOW").upper(),
                "risk_description": item.get("Risk", "No risk description available."),
                "remediation_advice": item.get("Remediation", {}).get("Recommendation", {}).get("Text", "Review AWS IAM/S3 policies manually.")
            }
            clean_cspm_findings.append(finding)
            
    logger.info(f"Successfully filtered and structured {len(clean_cspm_findings)} failed CSPM configurations.")
    return clean_cspm_findings