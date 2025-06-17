from typing import Dict, List
import gzip
import io
import csv
import requests
import os
import json

from .cvss_utils import is_valid_cvss_vector, parse_cvss_vector
from classes.dataclass import ScanResult
from utils.triage_priority_helper import determine_triage_priority
from .logger import *
from . import logger_instance as log



def get_epss_score(cves: List[str], epss_data: Dict[str, float]) -> float:
    # Let's return the highest EPSS score found for a list of CVES.
    scores = [epss_data.get(cve, 0) for cve in cves]
    return max(scores) if scores else 0

def is_cisa_kev(cves: List[str], kev_data: Dict[str, bool]) -> bool:
    # Check if any CVE is in the CISA KEV list. Return a boolean.
    return any(cve in kev_data for cve in cves)

#'''TODO: def enrich_with_shodan(ip_address):
#    Query Shodan with API Key
#    parse results: open ports, services, vulns, org
#    return {
#         "open_ports": [22, 80, 443],
#         "services": ["SSH", "HTTP", "HTTPS"],
#         "org": Example.org,
#         "shodan_tag": ["ics", "vpn"]
#    }
#    '''

def load_epss_from_csv(path_url: str) -> Dict[str, float]:
    '''
    Load EPSS data from a CSV file or URL into a dict {cve: epss_score}.
    CSV assumed to have columns: 'cve', 'epss_score'
    '''
    epss_data = {}
    
    def parse_csv(reader):
        for row in reader:
            cve = row.get('cve') or row.get('CVE')
            score_str = row.get('epss_score') or row.get('EPSScore') or row.get('score')
            if cve and score_str:
                try:
                    epss_data[cve.upper()] = float(score_str)
                except ValueError:
                    continue
    
    # Download or open local .gz file
    if path_url.startswith("http"):
        response = requests.get(path_url)
        response.raise_for_status()
        compressed_data = response.content
        # Open gzip file from bytes in memory
        with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
            # Read decoded text lines from gzip
            decoded = io.TextIOWrapper(gz, encoding='utf-8')
            reader = csv.DictReader(decoded)
            parse_csv(reader)
                    
    elif os.path.exists(path_url):
        # Local file
        if path_url.endswith('.csv'):
            with open(path_url, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                parse_csv(reader)
            
        else:
            # Local gzip file
            with gzip.open(path_url, mode='rt', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                parse_csv(reader)
                
    else:
        raise FileNotFoundError(f"File or URL not found: {path_url}")
    
    return epss_data

def load_kev_from_json(path_url: str) -> Dict[str, bool]:
    '''
    Load CISA KEV data from a JSON file or URL into a dict {cve: True}.
    JSON assumed to have CVE's under a 'cveID' or 'CVE' key in each entry
    '''
    kev_data = {}
    
    def parse_json(data):
        vulns = data.get('vulnerabilities', [])
        for entry in vulns:
            cve = entry.get('cveID') or entry.get('CVE')
            if cve:
                kev_data[cve.upper()] = True
                
    if path_url.startswith('http'):
        response = requests.get(path_url)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '')
        
        if 'application/gzip' in content_type or path_url.endswith('.gz'):
            compressed_data = response.content
            with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
                data = json.load(gz)
                parse_json(data)
        else:
            data = response.json()
            parse_json(data)
            
    elif os.path.exists(path_url):
        if path_url.endswith('.gz'):
            with gzip.open(path_url, 'rt', encoding='utf-8') as f:
                data = json.load(f)
                parse_json(data)
        else:
            with open(path_url, 'r', encoding='utf-8') as f:
                data = json.load(f)
                parse_json(data)
                
    else:
        raise FileNotFoundError(f'File or URL not found: {path_url}')
    
    return kev_data

def calculate_risk_score(cvss_score: float, exploit_available: bool, cisa_kev: bool, epss_score: float):
    raw_risk_score = cvss_score
    
    # Add enrichment weights
    if exploit_available:
        raw_risk_score += 2
    if cisa_kev:
        raw_risk_score += 2
    if epss_score >= 0.9:
        raw_risk_score += 2
    elif epss_score >= 0.7:
        raw_risk_score += 1
        
    # cap raw risk at 15 max.
    if raw_risk_score > 15.0:
        raw_risk_score = 15.0
        
    # Derived capped 0-10 operational risk score
    risk_score = min(raw_risk_score, 10.0)
    
    # Determine risk band
    risk_band = determine_risk_band(raw_risk_score)
    
    return raw_risk_score, risk_score, risk_band

def determine_risk_band(raw_risk_score):
    if raw_risk_score >= 12:
        return "Critical+"
    elif raw_risk_score >= 8:
        return "High"
    elif raw_risk_score >= 5:
        return "Medium"
    else:
        return "Low"
    
def update_enrichment_status(finding):
    if finding.exploit_available or finding.epss_score or finding.cisa_kev:
        finding.enriched = True
    else:
        finding.enriched = False

def enrich_scan_results(results: ScanResult, kev_data: Dict[str, bool] = None, epss_data: Dict[str, float] = None) -> None:
    '''
    Enrich the findings in a ScanResult object with EPSS Score, CISA KEV status, exploit indicators, and recalculate triage priority.
    
    Args:
        results (ScanResult Obj): The parsed vulnerability scan results.
        kev_data (Dict[str, bool], Optional): Mapping of CVE IDs to CISA KEV status.
        epss_data (Dict[str, float], Optional): Mapping of CVE IDs to EPSS Scores.
    '''
    miss_logger = EnrichmentMissLogger()
    
    baseline_risk_count = 0
    total_cves = 0
    total_kev_hits = 0
    total_epss_misses = 0
    
    kev_data = kev_data or {}
    epss_data = epss_data or {}
    
    
    for asset in results.assets:
        for finding in asset.findings:
            cisa_hits = []
            epss_scores = []
            enrichment_attempted = False
            
            for cve in finding.cves:
                total_cves += 1
                enrichment_attempted = True
                
                # CISA KEV Enrichment
                kev_hit = kev_data.get(cve.upper(), False)
                cisa_hits.append(kev_hit)
                if kev_hit:
                    total_kev_hits += 1
                    log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} {cve} found in CISA KEV")
                else:
                    log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} No CISA KEV record for {cve}")
                    miss_logger.log_miss(cve, cisa_kev=False, epss_score=None)
                    
                # EPSS Score Enrichment
                epss_score = epss_data.get(cve)
                if epss_score is not None:
                    epss_scores.append(epss_score)
                    log.log.print_info(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} {cve} EPSS Score: {epss_score}")
                else:
                    log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} No EPSS Score for {cve}")
                    epss_scores.append(0.0)
                    total_epss_misses += 1
                    miss_logger.log_miss(cve, cisa_kev=kev_hit, epss_score=None)

            # Assign KEV and max EPSS to finding level
            finding.cisa_kev = any(cisa_hits)
            finding.epss_score = max(epss_scores) if epss_scores else 0.0
                
            # Get CVSS Vectors w/ Validation / Reconciliation
            vector = finding.cvss_vector
            if vector:
                if is_valid_cvss_vector(vector):
                    cvss_data = parse_cvss_vector(vector)
                    log.log.print_info(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} Validating and reconciling CVSS Vector...")
                    if cvss_data:
                        log.log.print_info(f"{finding.vuln_id} Base score from vector: {cvss_data[0]}")
                        
                        # Auto-Reconcile CVSS base score if it differs by tolerance.
                        if abs(cvss_data[0] - (finding.cvss_score or 0.0)) > 0.1:
                            log.log.print_warning(f"Score mismatch for {finding.vuln_id}: vector {cvss_data[0]} vs field: {finding.cvss_score}")
                            log.log.print_success(f"Overwriting cvss score with value from CVSS Vector: {cvss_data[0]}")
                            finding.cvss_score = cvss_data[0]
                            
                    else:
                        log.logger.debug(f"Invalid CVSS vector for {finding.vuln_id}")
                else:
                    log.log.print_error(f"Invalid CVSS vector format for {finding.vuln_id}: {vector}")
                    
            # Calculate Risk_Score
            cvss = finding.cvss_score or 0.0
            epss = finding.epss_score or 0.01 # Prevent zero-risk bias
            
            # Baseline risk adjustment if missing CVSS but has exploit/high+ severity or risk band
            if cvss == 0.0 and (finding.exploit_available or finding.severity in ['Critical', 'High']):
                baseline_risk_count += 1
                baseline_risk = 7
                log.log.print_warning(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} Missing CVSS for {finding.vuln_id}, setting baseline risk {Fore.LIGHTRED_EX}{baseline_risk}{Style.RESET_ALL} due to exploit/high-critical severity")
                cvss = baseline_risk
            
            # Risk Calculation
            raw_risk_score, risk_score, risk_band = calculate_risk_score(
                cvss_score=cvss,
                exploit_available=finding.exploit_available,
                cisa_kev=finding.cisa_kev,
                epss_score=epss
            )
            if raw_risk_score > 10.0:
                log.log.print_warning(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} Risk Score for {finding.vuln_id} capped at 10.0 (Raw Score: {Fore.LIGHTRED_EX}{raw_risk_score}{Style.RESET_ALL})")
            else:
                log.log.print_info(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} {finding.vuln_id} Raw Risk Score: {Fore.LIGHTRED_EX}{raw_risk_score}{Style.RESET_ALL}")
            log.log.print_info(f"{Fore.LIGHTRED_EX}[RiskCalc]{Style.RESET_ALL} {finding.vuln_id} Final Risk Score: {Fore.LIGHTRED_EX}{risk_score}{Style.RESET_ALL} | Triage Priority: {Fore.LIGHTRED_EX}{risk_band}{Style.RESET_ALL} | ")
            
            # Set risk score attribs
            finding.raw_risk_score=raw_risk_score
            finding.risk_score=risk_score
            finding.risk_band=risk_band

                
            # Recalculate Triage Priority
            finding.triage_priority = determine_triage_priority(
                finding.severity,
                cvss,
                epss,
                finding.cisa_kev,
                finding.exploit_available
            )
            
            # Update enrichment flag
            finding.enriched = enrichment_attempted and (
                any(cisa_hits) or
                any(score > 0.1 for score in epss_scores) or
                finding.exploit_available)
            
        asset.avg_risk_score = round(
            sum(f.risk_score for f in asset.findings) / len(asset.findings), 2
        ) if asset.findings else 0.0
        
        print(f"{Fore.LIGHTMAGENTA_EX}==============[Enrichment Summary]=============={Style.RESET_ALL}")
        log.log.print_info(f"   Total CVEs Processed : {total_cves}")
        log.log.print_info(f"   Total CISA KEV Hits : {total_kev_hits}")
        log.log.print_info(f"   Total EPSS Misses : {total_epss_misses}")
        log.log.print_info(f"   Total Findings Rx Baseline Risk Adjustment: {baseline_risk_count}")
        print(f"{Fore.LIGHTMAGENTA_EX}============[Enrichment Summary End]============{Style.RESET_ALL}")
        
        miss_logger.write_log()