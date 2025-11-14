from datetime import datetime, timezone
from lxml import etree
from typing import Dict, Optional
from .base_parser import BaseParser
from classes.dataclass import ScanMetaData, ScanResult, Asset, Finding
import utils.logger_instance as log
import os

class NessusXMLParser(BaseParser):
    @classmethod
    def detect_file(cls, filepath):
        """Detect if the file is a Nessus XML export (.nessus)"""
        if filepath.lower().endswith((".nessus", ".xml")):
            try:
                # Size guardrail (Lets do >500MB)
                if os.path.getsize(filepath) > 500 * 1024 * 1024:
                    log.log.print_error(f"File supplied exceeds 500MB. This is a mechanism to protect against DOS. File: {filepath}")
                    return False
                
                # Setup Parser
                parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
                tree = etree.parse(filepath, parser)
                root = tree.getroot()
                
                # Valid Nessus report must have root and at least one ReportItem to look for.
                return root.tag == "NessusClientData_v2" and root.find(".//ReportItem") is not None
            except Exception:
                return False
        return False
    
    
    def parse(self) -> ScanResult:
        """Parse Nessus XML (.nessus) into a ScanResult with Assets + Findings."""
        if not self.filepath:
            raise ValueError("NessusXMLParser requires an accessible filepath.")
        
        parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
        tree = etree.parse(self.filepath, parser)
        root = tree.getroot()
        
        
        assets: Dict[str, Asset] = {}
        
        # Loop through each host in the report
        for report in root.findall("Report"):
            # Gather hostname and host metadata.
            report_name = report.attrib.get("name")
            for hostelem in report.findall("ReportHost"):
                ip_or_host = hostelem.attrib.get("name")
                asset_id = ip_or_host
                
                os_name: Optional[str] = None
                scan_date: Optional[str] = None
                # Host Metadata
                host_props = hostelem.find("HostProperties")
                if host_props is not None:
                    for tag in host_props.findall("tag"):
                        if tag.attrib.get("name") == "operating-system":
                            os_name = tag.text
                        if tag.attrib.get("name") == "HOST_START":
                            scan_date = tag.text   
            
                if asset_id not in assets:
                    # build Asset
                    assets[asset_id] = Asset(
                        hostname=ip_or_host,
                        ip_address=ip_or_host,
                        criticality=None,
                        os=os_name,
                        findings=[],
                        shodan_data=None
                    )
            
            # Each ReportItem = vuln finding and derive fields + fallbacks
            for report_item in hostelem.findall("ReportItem"):
                
                vuln_id=report_item.get("pluginID")
                title=self._safe_text(report_item.attrib.get("pluginName")) or self._safe_text(report_item.findtext("plugin_name"))
                description=self._safe_text(report_item.findtext("description"))
                raw_output = self._safe_text(report_item.findtext("plugin_output"))
                log.log.logger.info(f"[NESSUSXMLPARSER] Logging raw plugin output for finding {title}: plugin_output: {raw_output}")
                summary, evidence = self._summarize_plugin_output(raw_output, max_lines=5)
                plugin_output = summary
                if not description:
                    description = plugin_output or "SENTINEL:Not_Available"
                severity=report_item.attrib.get("severity")
                cvss_score=self._safe_float(report_item.findtext("cvss3_base_score")) or self._safe_float(report_item.findtext("cvss_base_score"))
                cvss_vector=self._safe_text(report_item.findtext("cvss3_vector")) or self._safe_text(report_item.findtext("cvss_vector")) or "SENTINEL:Attempted_NotFound"
                cves=[cve.text for cve in report_item.findall("cve")]
                epss_score = self._safe_float(report_item.findtext("epss_score"))
                affected_port=self._safe_int(report_item.attrib.get("port"))
                protocol=self._safe_text(report_item.attrib.get("protocol"))
                solution=self._safe_text(report_item.findtext("solution"))
                risk=self._safe_text(report_item.findtext("risk_factor"))
                
                
                finding = Finding(
                    vuln_id=vuln_id,
                    title=title,
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector or "N/A",
                    cves=cves,
                    epss_score=epss_score,
                    risk=risk,
                    affected_port=affected_port,
                    protocol=protocol,
                    plugin_output=plugin_output,
                    plugin_evidence=evidence,
                    solution=solution,
                    detection_plugin=title,
                    assetid=ip_or_host,
                )
                
                assets[asset_id].findings.append(finding)
            
            asset_count = len(assets)
            vuln_count = sum(len(asset.findings) for asset in assets.values())
            
            metadata = ScanMetaData(
            source="Nessus",
            scan_name=report_name,
            scan_date=scan_date if scan_date else "SENTINEL:Date_Unavailable",
            source_file=str(self.filepath),
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            parsed_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            )
            
        return ScanResult(scan_metadata=metadata, assets=list(assets.values()))
    
    