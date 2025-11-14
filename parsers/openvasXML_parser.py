from lxml import etree
from datetime import datetime, timezone
import os
import utils.logger_instance as log
from typing import Dict, Optional
from .base_parser import BaseParser
from classes.dataclass import ScanMetaData, ScanResult, Asset, Finding

class OpenVASXMLParser(BaseParser):
    @classmethod
    def detect_file(cls, filepath):
        """Detect if the file is an OpenVAS XML file."""
        if filepath.lower().endswith(".xml"):
            try:
                if os.path.getsize(filepath) > 500 * 1024 * 1024:
                    log.log.print_error(f"File supplied exceeds 500MB. This is a mechanism to protect against DOS. File: {filepath}")
                    return False

                # Setup Parser
                parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
                tree = etree.parse(filepath, parser)
                root = tree.getroot()
                
                # Validate OpenVAS report with root tag
                has_report = root.tag == "report" or root.find(".//report") is not None
                has_nvt = root.find(".//nvt") is not None
                
                return has_report and has_nvt
            except Exception:
                return False
        return False
    
    def parse(self) -> ScanResult:
        """Parse OpenVAS XML into ScanResult object with Assets + Findings."""
        if not self.filepath:
            raise ValueError("OpenVASXMLParser requires an accessible filepath.")
        
        
        parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
        tree = etree.parse(self.filepath, parser)
        root = tree.getroot()
        
        assets: Dict[str, Asset] = {}
        
        scan_date = root.findtext(".//creation_time") or "SENTINEL:Date_Unavailable"
        scan_name = root.attrib.get("id") or "SENTINEL:Not_Found"
        
        # Start Parsing
        for result in root.findall(".//result"):
            host = result.findtext("host") or "SENTINEL:No_Hostname"
            port = self._safe_int(self._parse_port(result.findtext("port")))
            protocol = self._safe_text(self._parse_protocol(result.findtext("port")))
            description = self._safe_text(result.findtext("description")) or "SENTINEL:No_Description"
            severity = self._safe_text(result.findtext("threat"))
            
            # Collect NVT Field
            nvt_field = result.find("nvt")
            cvss_score = None
            cvss_vector = None
            cves = []
            if nvt_field is not None:
                tags = nvt_field.findtext("tags") or ""
                if tags is None:
                    print(f"[DEBUG] YO TAGS IS NULL FAM")
                title = nvt_field.findtext("name")
                cvss_vector = ((result.findtext(".//severities/severity/value") or "").strip() or self._extract_from_tags(tags, "cvss_base_vector=") or "SENTINEL:Vector_Unavailable")
                cvss_score = self._safe_float(nvt_field.findtext("cvss_base"))
                solution = self._safe_text(nvt_field.findtext("solution"))
                # Plugin_Output
                plugin_output = self._extract_from_tags(tags, "summary=")
                # Grab CVEs
                cves = [
                    ref.text.strip() for ref in nvt_field.findall(".//refs/ref[@type='cve']") if ref.text
                ] or ["SENTINEL:No_CVE_Listed"]
                
            # Build out evidence values and other potentially valuable information
            detection = result.find("detection")
            
            evidence = []
            if detection is not None:
                for detail in detection.findall(".//detail"):
                    name = detail.findtext("name") or "Unknown"
                    value = detail.findtext("value") or "N/A"
                    evidence.append(f"{name}: {value}")
                    
            summary, summarized_evidence = self._summarize_plugin_output(plugin_output)
            if not evidence:
                evidence = summarized_evidence

            # Now time for Asset Creation
            if host not in assets:
                assets[host] = Asset(
                    hostname=host,
                    ip_address=host,
                    criticality=None,
                    os=None,
                    findings=[],
                    shodan_data=None,
                )
            
            # Build Finding
            finding = Finding(
                vuln_id=nvt_field.attrib.get("oid") if nvt_field is not None else "SENTINEL:No_OID",
                title=title or "SENTINEL:No_Title",
                description=description,
                severity=severity,
                cves=cves,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                epss_score=None,
                risk=None,
                affected_port=port,
                protocol=protocol,
                plugin_output=plugin_output or "SENTINEL:No_Plugin_Output",
                plugin_evidence=summarized_evidence or evidence or "SENTINEL:No_Evidence",
                solution=solution or "SENTINEL:No_Solution",
                detection_plugin=title or "SENTINEL:No_Detection_Plugin",
                assetid=host,
            )
            assets[host].findings.append(finding)
        
        asset_count = len(assets)
        vuln_count = sum(len(asset.findings) for asset in assets.values())
        
        # Build Metadata
        metadata = ScanMetaData(
            source="OpenVAS",
            scan_name=scan_name,
            scan_date=scan_date,
            source_file=str(self.filepath),
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            parsed_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        )
            
        return ScanResult(scan_metadata=metadata, assets=list(assets.values()))
                
    def _extract_cves(self, nvt_elem, result_elem):
        cves = []
        if nvt_elem is not None:
            cves.extend(self._safe_text(c.text) for c in nvt_elem.findall("cve") if c is not None and c.text)
        # CVEs in tags/reference fallback
        tags_text = self._safe_text(result_elem.findtext("tags")) or self._safe_text(result_elem.findtext("references"))
        if tags_text:
            import re
            cves.extend(re.findall(rf"CVE-\d{4}-\d{4,7}", tags_text))
        
        # Dedup & keep order
        seen = set(); out = []
        for cv in cves:
            if cv and cv not in seen:
                seen.add(cv); out.append(cv)
        return out
    
    def _extract_cvss(self, nvt_elem, result_elem):
        """
        Prefer CVSS v3 if present, else fall back to v2.
        Accept score/vector from either <nvt> or <result>.
        """
        # Score Candidates
        score_candidates = [
            nvt_elem.findtext("cvss3_base") if nvt_elem is not None else None,
            nvt_elem.findtext("cvss_base") if nvt_elem is not None else None,
            result_elem.findtext("cvss3_base"),
            result_elem.findtext("cvss_base"),
            nvt_elem.findtext("cvss_base_score") if nvt_elem is not None else None,
            result_elem.findtext("cvss_base_score"),
        ]
        score = next((self._safe_float(s) for s in score_candidates if s), None)
        
        # Vector Candidates
        vector_candidates = [
            nvt_elem.findtext("cvss3_vector") if nvt_elem is not None else None,
            nvt_elem.findtext("cvss_base_vector") if nvt_elem is not None else None,
            nvt_elem.findtext("cvss_vector") if nvt_elem is not None else None,
            result_elem.findtext("cvss3_vector"),
            result_elem.findtext("cvss_vector"),
        ]
        vector = next((self._safe_text(v) for v in vector_candidates if v), None)
        
        return score, vector
    
    @staticmethod            
    def _extract_nvd_oid(result_elem) -> Optional[str]:
        """Extract the NVT OID"""
        nvt = result_elem.find("nvt")
        if nvt is not None:
            return nvt.get("oid")
        return None
    
    @staticmethod
    def _parse_port(port_field: Optional[str]) -> Optional[str]:
        """Convert ##/tcp to ##"""
        if not port_field:
            return None
        try:
            return int(port_field.split("/")[0])
        except ValueError:
            return None
        
    @staticmethod
    def _parse_protocol(port_field: Optional[str]) -> Optional[str]:
        """Extract protocol from port field"""
        if not port_field or "/" not in port_field:
            return None
        return port_field.split("/")[1]
    
    @staticmethod
    def _extract_from_tags(tags_text: str, key: str) -> Optional[str]:
        if not tags_text or key not in tags_text:
            return None
        for item in tags_text.split('|'):
            if item.strip().startswith(key):
                return item.split('=', 1)[1].strip()
        return None