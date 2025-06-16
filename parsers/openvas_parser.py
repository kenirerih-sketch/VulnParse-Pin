
from datetime import datetime, timezone
from email.policy import default
import hashlib
from multiprocessing import Value
from json_parser import get_key_case_ins
import utils.logger_instance as log
from typing import Any, Counter, Dict, List, Optional
from classes.dataclass import ScanResult, ScanMetaData, Asset, Finding
from parsers.base_parser import BaseParser
from utils.normalizer import coerce_float, coerce_int, coerce_list, coerce_severity, coerce_str


class OpenVASParser(BaseParser):
    def detect(self, data):
        detection_patterns = [
            # Pattern 1: Check for top-level 'report' key with 'results' list with nested dictionaries
            lambda d: "report" in d and isinstance(d["report"].get("results"), list),
            
            # Pattern 2: Check for flat openvas schema. 'scan_id' and 'vulns'[] key
            lambda d: isinstance(d, dict) and self.get_key_cins(data, ["scan_id", "vulns"])
        ]
        
        for pattern in detection_patterns:
            try:
                if pattern(data):
                    return True
            except Exception as e:
                log.log.print_error(f"Pattern check failed: {e}")
                continue
            
        return False
    
    def parse(self, openvasdata: Dict[str, Any]) -> ScanResult:
        '''
        Parse a OpenVAS JSON vulnerability scan report into structured Python objects.
        
        Args:
            data (Dict[str, Any]): The JSON OpenVAS scan report.
            
        Returns:
            ScanResult: An object containing structured scan metadata, assets, and vulnerability findings.
        '''
        # Check if it's flat json. if not, continue.
        metadata, report_data = self.normalize_structure(openvasdata)
        
        metadata_time = metadata
        
        assets: Dict[str, Asset] = {}
        
        
        for item in report_data["results"]:
            hostname = coerce_str(self.get_key_cins(item, ["host", "hostname", "host-name", "host_name"], default="N/A"))
            ip_address = coerce_str(self.get_key_cins(item, ["ip", "host-ip", "ip-address", "ip_address", "host_ip"], default="N/A"))
            asset_id_raw = hostname or ip_address or "N/A"
            asset_id = coerce_str(asset_id_raw, default="N/A")
            
            if asset_id not in assets:
                assets[asset_id] = Asset(
                    hostname=hostname,
                    ip_address=ip_address,
                    criticality=None,
                    findings=[],
                    shodan_data=None
                )
                
                
            tags = self.get_key_cins(item.get("nvt", {}), ["tags"], default="")


            vuln_id = self.get_vuln_id(item)
            title = coerce_str(self.get_key_cins(item["nvt"], ["name", "title"], default="N/A"))
            description = coerce_str(self.get_key_cins(item, ["description"], default="N/A"))
            severity = coerce_severity(self.get_key_cins(item, ["threat", "severity"], default="N/A"))
            cves_raw = self.convert_cves_str_list(self.get_key_cins(item.get("nvt", {}), ["cve", "cves"], default=[]))
            cvss_score = self.parse_cvss_score(tags)
            if not cvss_score:
                coerce_float(self.get_key_cins(item["nvt"], ["cvss_base", "cvss", "cvss_score", "cvss_base_score"], default=0.0))
            cvss_vector = coerce_str(self.get_key_cins(item["nvt"], ["cvss_base_vector", "cvss_vector"], default="N/A"))
            references_raw = coerce_str(self.get_key_cins(item["nvt"], ["tags", "references"], default=""))
            references_list = coerce_list([ref.strip() for ref in references_raw.split(";")] if references_raw else [])
            affected_port_raw = coerce_str(self.get_key_cins(item, ["port"], default="N/A"))
            affected_port = coerce_int(affected_port_raw.split("/")[0])
            solution = coerce_str(self.get_key_cins(item, ["solution"], default="N/A"))
            protocol = coerce_str(self.get_key_cins(item, ["port"], default="N/A")).split("/")[1]
            
            exploit_indicators = ["exploit", "metasploit", "public exploit", "poc available", "poc"]
            search_text = f"{solution or ''} {description or ''}".lower()
            exploit_available = any(indicator in search_text for indicator in exploit_indicators)
            
            
            finding = Finding(
                vuln_id=vuln_id,
                title=title,
                severity=severity,
                description=description,
                solution=solution,
                cves=cves_raw,
                cvss_score=cvss_score or 0.0,
                cvss_vector=cvss_vector,
                epss_score=0.0,
                cisa_kev=False,
                exploit_available=exploit_available,
                risk=None,
                triage_priority=None,
                enriched=False,
                affected_port=affected_port,
                protocol=protocol,
                references=references_list,
                detection_plugin=title,
                assetid=asset_id
            )
            
            assets[asset_id].findings.append(finding)
            
        for asset in assets.values():
            # Determine criticality
            severity_counter = Counter(finding.severity for finding in asset.findings)
            asset.criticality = self.determine_asset_criticality(severity_counter)
            
        asset_count = len(assets)
        vuln_count = sum(len(asset.findings) for asset in assets.values())
        
        metadata_final = ScanMetaData(
            source="OpenVAS",
            scan_date=metadata_time,
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            parsed_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        )
        
        result = ScanResult(
            scan_metadata=metadata_final,
            assets=list(assets.values())
        )
        return result

    def get_key_cins(self, data: Dict[str, Any], possible_keys: List[str], default: Optional[Any] = None) -> Any:
        for key in possible_keys:
            for actual_key in data.keys():
                if actual_key.lower() == key.lower():
                    return data[actual_key]
        return default
    
    def detect_and_transform_flat_json(self, data: Dict[str, Any]):
        if isinstance(data, dict) and self.get_key_cins(data, ["scan_id", "vulns"]):
            log.log.print_info("Detected OpenVas flat JSON format w/ 'vulns' list of hosts")
            # Transform flat JSON into standard structure.
            results = []
            hosts = data.get("vulns")
            if hosts:
                for host in hosts:
                    # Normalize some fields first before building assets and findings.
                    severity = host.get("severity", "N/A")
                    if str(severity).isdigit():
                        severity = self.convert_sev_num(severity)
                    cves = self.get_key_cins(host, ["cves", "cve"], default="")
                    if cves:
                        cves = self.convert_cves_str_list(cves)
                    port = host.get("port", "N/A")
                        
                    result_item = {
                        "host": self.get_key_cins(host, ["host", "hostname", "host-id", "host_name", "host-name"], default="N/A"),
                        "ip": self.get_key_cins(host, ["ip", "ip_address", "host-ip", "ip-address", "host"], default="N/A"),
                        "port": port,
                        "description": self.get_key_cins(host, ["description"], default="N/A"),
                        "severity": severity,
                        "threat": self.get_key_cins(host, ["threat", "severity"], default="N/A"),
                        "solution": self.get_key_cins(host, ["solution"], default="N/A"),
                        "nvt": {
                            "cve": cves,
                            "cvss_base_vector": self.get_key_cins(host, ["cvss_base_vector"], default=""),
                            "name": self.get_key_cins(host, ["name"], default="N/A"),
                            "cvss_base": self.get_key_cins(host, ["cvss_base", "cvss_base_score", "cvss"], default="N/A"),
                            "tags": self.get_key_cins(host, ["tags", "references"], default="N/A")
                        }
                    }
                    results.append(result_item)
                    
                if not isinstance(results, list):
                    raise ValueError("[FlatJSONTransform] Transformation failed, 'results' is not a list.")
                return {
                    "report": {
                        "scan_start": data.get("scan_start", "N/A"),
                        "scan_end": data.get("scan_end", "N/A"),
                        "results": results
                    }
                }
            else:
                log.log.print_error("vulns list is empty. Unable to transform schema.")
        else:
            log.log.print_warning("Unknown dict formation - returning as-is.")
            return data
    
    # Big Normalizer
    
    def normalize_structure(self, data):
        if isinstance(data, list):
            if len(data) > 0:
                data = data[0]
            else:
                raise ValueError("Empty list provided - no data to normalize")
            
        elif self.is_openvas_standard(data):
            return self.normalize_openvas_standard(data)
        
        elif self.is_flat_openvas(data):
            # For already transformed flat JSON by detect_and_transform_flat_json
            transformed = self.detect_and_transform_flat_json(data)
            return self.normalize_openvas_standard(transformed)
        
        else:
            raise ValueError("Unknown or unsupported OpenVAS data structure for normalization.")
            
    # -----------------------------------------------------------------------------------        
            
    # Schema Detectors
    def is_openvas_standard(self, data):
        return isinstance(data, dict) and "report" in data and isinstance(data["report"].get("results"), list)
    
    def is_flat_openvas(self, data):
        return isinstance(data, dict) and self.get_key_cins(data, ["scan_id", "vulns"])
    # -------------------------------------------------------------------------------
    
    # Normalizers
    def normalize_openvas_standard(self, data):
        report = data["report"]
        scan_start = data["report"].get("scan_start", "N/A")
        scan_end = data["report"].get("scan_end", "N/A")
        metadata = (scan_start, scan_end)
        
        return metadata[0], report
    
    # -------------------------------------------------------------------------------------
    
    def determine_asset_criticality(self, severity_counter: Counter) -> str:
        crit_count: int = severity_counter["Critical"]
        high_count: int = severity_counter["High"]
        
        if crit_count >= 3:
            return "Extreme"
        elif crit_count >= 1 or high_count >= 2:
            return "High"
        elif high_count == 1:
            return "Medium"
        else:
            return "Low"
        
    def parse_cvss_score(self, tags_str: str) -> float:
        if not tags_str:
            return 0.0
        
        for pair in tags_str.split(";"):
            if pair.startswith("cvss_base_score="):
                _, val = pair.split('=', 1)
                try:
                    return float(val)
                except ValueError:
                    log.log.print_error(f"Value Error occured.")
                    log.log.logger.exception("ValueError Exception")
                    return 0.0

        return 0.0
    
    def convert_sev_num(self, value):
        value = float(value)
        
        if value >= 8.5:
            return "Critical"
        elif value >= 6.5:
            return "High"
        elif value >= 5.0:
            return "Medium"
        else:
            return "Low"
        
    def convert_cves_str_list(self, cvestype):
        if isinstance(cvestype, str):
            cvestype = coerce_list([c.strip() for c in cvestype.split(",")])
            return cvestype
        elif isinstance(cvestype, list):
            return list(cvestype)
        else:
            return []
        
    def get_vuln_id(self, item):
        nvt_key = item.get("nvt", {})
        
        try:
            vuln_id = nvt_key.get("cve") or nvt_key.get("oid")
            if isinstance(vuln_id, list):
                return vuln_id[0]
            elif isinstance(vuln_id, str) and vuln_id.strip():
                return [c.strip() for c in vuln_id.split(",") if c.strip()][0]
        except (ValueError, IndexError, KeyError, TypeError) as e:
            log.log.print_error(f"ValueError when retrieving vuln_id: {e}")
        
        host = item.get("host", "unknown_post")
        port = item.get("port", "unknown_port")
        title = nvt_key.get("name", "unknown_title")
        
        data_to_hash = f"{host}:{port}:{title}"
        
        log.log.print_info(f"No vuln_id found - generating fallback hash for {host}:{port}:{title}")
        
        hashed_fb = hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()[:12]
        
        return str(hashed_fb)
            