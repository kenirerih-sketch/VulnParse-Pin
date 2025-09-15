import csv
from typing import List, Any
from classes.dataclass import ScanResult
import utils.logger_instance as log

def _flatten_exploits(exploit_refs: dict[str, list[dict]]) -> tuple[str, str, str]:
    """
    Flatten exploit refs into semicolon-separated strings.
    
    Returns:
        (ids, titles, urls) as strings
    """
    if not exploit_refs:
        return ("", "", "")
    
    
    ids, titles, urls = [], [], []
    
    # case 1: dict
    if isinstance(exploit_refs, dict):
        for cve, refs in exploit_refs.items():
            for ref in refs:
                ids.append(f"{cve}:{ref.get("exploit_id", "")}")
                titles.append(f"{cve}:{ref.get("title", "")}")
                urls.append(f"{cve}:{ref.get("url", "")}")
            
        return ";".join(ids), ";".join(titles), ";".join(urls)

def export_to_csv(scan_result: ScanResult, csv_path: str) -> None:
    """
    Export scan findings to a CSV file.
    
    Args:
        scan_result (ScanResult): Parsed & enriched results
        csv_path (str): Destination CSV file path
    """
    
    # Flatten findings
    rows = []
    for asset in scan_result.assets:
        for finding in asset.findings:
            exploit_ids, exploit_titles, exploit_urls = _flatten_exploits(finding.exploit_references)
            
            
            rows.append({
                "asset_hostname": asset.hostname or "",
                "asset_ip": asset.ip_address or "",
                "asset_criticality": asset.criticality or "",
                "asset_avg_risk_score": asset.avg_risk_score,
                "vuln_id": finding.vuln_id or "",
                "title": finding.title or "",
                "severity": finding.severity or "",
                "authoritative_cve": getattr(finding, "enrichment_source_cve", "") or "",
                "cves": ";".join(map(str, finding.cves)) if finding.cves else "",
                "cvss_score": finding.cvss_score,
                "epss_score": finding.epss_score,
                "cisa_kev": "TRUE" if finding.cisa_kev else "FALSE",
                "exploit_available": "TRUE" if (bool(finding.exploit_references) or finding.cisa_kev) else "FALSE",
                "exploit_ids": exploit_ids,
                "exploit_titles": exploit_titles,
                "exploit_urls": exploit_urls,
                "risk_score": finding.risk_score,
                "raw_risk_score": finding.raw_risk_score,
                "risk_band": finding.risk_band or "",
                "triage_priority": finding.triage_priority or "",
                "solution": finding.solution or "",
                "description": finding.description or "",
            })
            
    if not rows:
        log.log.warning("No findings to export. Skipping CSV write.")
        return
            
    fieldnames = rows[0].keys() if rows else []
    with open(csv_path, 'w', newline="", encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        
    log.log.print_success(f"Results exported to CSV: {csv_path}")