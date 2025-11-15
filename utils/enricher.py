from datetime import datetime, timezone
import hashlib
from json import scanner
import random
import time
from typing import Any, Dict, List, Optional, Tuple
import gzip
import io
import csv
from bs4 import BeautifulSoup
import requests
import os
import json
import re
from utils.enrichment_stats import stats

from utils.cve_selector import select_authoritative_cve
from .cvss_utils import CVSS3_REGEX_L, detect_cvss_version, is_valid_cvss_vector, parse_cvss_vector
from classes.dataclass import ScanResult, TriageConfig
from utils.triage_priority_helper import determine_triage_priority
from .logger import *
from . import logger_instance as log

triagecfg = TriageConfig()

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

def print_cache_metadata(cache_path: str):
    meta_path = cache_path + ".meta"
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            meta = json.load(f)
            log.log.print_info(f"{os.path.basename(cache_path)} last updated: {meta['last_updated']}")

def save_metadata_file(cache_path: str, source_url: str):
    meta_path = cache_path + ".meta"
    metadata = {
        "last_updated": datetime.now(timezone.utc).isoformat().replace("00:00", "Z"),
        "source_url": source_url,
        "fetched_by": "vulnparse-pin v1.0"
    }
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    log.log.print_info(f"Metadata written to {meta_path}")

def save_with_checksum(data_byes: bytes, cache_path: str):
    # Save the data
    with open(cache_path, 'wb') as f:
        f.write(data_byes)
        
    # Save checksum
    sha256 = hashlib.sha256(data_byes).hexdigest()
    with open(cache_path + ".sha256", 'w') as f:
        f.write(sha256)

def validate_checksum(cache_path: str) -> bool:
    '''
    Validates the checksum of a cached file (either .json or .csv.gz) using corresponding .sha256 file.
    
    Args:
        cache_path (str): Base path without extension.
        
    Returns:
        bool: True if checksum is valid, False otherwise.
    '''
    
    if not os.path.exists(cache_path):
        log.log.print_error(f"File not found: {cache_path}")
        return False

    checksum_path = cache_path + ".sha256"
    
    if not os.path.exists(checksum_path):
        log.log.print_warning(f"No checksum found for cache file: {cache_path}")
        return False
    
    try:
        with open(cache_path, 'rb') as f:
            file_data = f.read()
            computed_hash = hashlib.sha256(file_data).hexdigest()
            
        with open(checksum_path, 'r') as f:
            expected_hash = f.read().strip()
            
        if computed_hash == expected_hash:
            log.log.print_success(f"Checksum valid for {cache_path}!")
            return True
        else:
            log.log.print_error(f"Checksum mismatch for {cache_path}")
            log.log.print_error(f"Expected: {expected_hash}")
            log.log.print_error(f"Computed: {computed_hash}")
            return False
        
    except Exception as e:
        log.log.print_error(f"Error validating checksum for {cache_path}")
        return False



def load_epss_from_csv(path_url: str, cache_path: str = "./data/epss_cache.csv.gz") -> Dict[str, float]:
    '''
    Load EPSS data from a CSV file or URL into a dict {cve: epss_score}.
    CSV assumed to have columns: 'cve', 'epss_score'
    '''
    epss_data = {}
    
    def parse_csv(reader):
        for row in reader:
            cve = row.get('cve') or row.get('CVE')
            
            if not cve:
                for header in row:
                    if re.search(r"model_version", header, re.IGNORECASE):
                        cve = row.get(header)
                        break
            score_str = row.get('epss_score') or row.get('EPSScore') or row.get('score') or row.get('epss')
            
            if not score_str:
                for header in row:
                    if re.search(r"score_date", header, re.IGNORECASE):
                        score_str = row.get(header)
                        break
            if cve and score_str:
                try:
                    epss_data[cve.upper()] = float(score_str)
                except ValueError:
                    continue
    
    # Download or open local .gz file
    if path_url.startswith("http"):
        response = requests.get(path_url, timeout=5, allow_redirects=True, headers={
            "User-Agent": "VulnParse-PinV1.0/Dev"
        })
        response.raise_for_status()
        compressed_data = response.content
        
        # Save downloaded content to local cache
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, 'wb') as f:
            f.write(response.content)
        
        # Save checksum
        save_with_checksum(response.content, cache_path)
        log.log.print_success(f"EPSS feed cached locally at {cache_path}")
        save_metadata_file(cache_path, "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
        
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
    
    if epss_data is None:
        log.log.print_error(f"Error loading epss_data. EPSS_Data is empty: {epss_data}")
        
    if not validate_checksum("./data/epss_cache.csv.gz"):
        raise ValueError(f"Corrupted or tampered cache file: {cache_path}")
    
    print_cache_metadata(cache_path)
    
    return epss_data

def load_kev_from_json(path_url: str, cache_path: str = "./data/kev_cache.json.gz") -> Dict[str, bool]:
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
        response = requests.get(path_url, allow_redirects=True, timeout=5, headers={
            "User-Agent": "VulnParse-PinV1.0/Dev"
        })
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '')
        
        if 'application/gzip' in content_type or path_url.endswith('.gz'):
            compressed_data = response.content
            
            # Save content to local cache
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, 'wb') as f:
                f.write(response.content)
                
            # Save with checksum
            save_with_checksum(response.content, cache_path)
            log.log.print_success(f"KEV feed cached locally at {cache_path}")
            save_metadata_file(cache_path, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            
            with gzip.GzipFile(fileobj=io.BytesIO(compressed_data)) as gz:
                data = json.load(gz)
                parse_json(data)
        else:
            # Save json data content to local cache
            os.makedirs(os.path.dirname("./data/kev_cache.json"), exist_ok=True)
            with open("./data/kev_cache.json", 'w', encoding='utf-8') as f:
                json.dump(response.json(), f, indent=2)
            # Save with checksum
            save_with_checksum(response.content, "./data/kev_cache.json")
            log.log.print_success(f"KEV JSON feed cached locally at {cache_path}")
            save_metadata_file("./data/kev_cache.json", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            
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
    
    for path in ["./data/kev_cache.json", "./data/kev_cache.json.gz"]:
        if os.path.exists(path) and validate_checksum(path):
            break
    else:
        raise ValueError(f"Corrupted or tampered cache file: {path}")
        
    for path in ["./data/kev_cache.json", "./data/kev_cache.json.gz"]:
        if os.path.exists(path):
            print_cache_metadata(path)
            break
    
    return kev_data

def load_config_json(config_name="config.json"):
    """
    Load config from a JSON file.
    """
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", config_name)
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        log.log.print_error(f"Unable to load config file: {e}")
        return {}
    
config = load_config_json()

def calculate_risk_score(cvss_score: float, exploit_available: bool, cisa_kev: bool, epss_score: float, config: dict):
    weights = config["weights"]
    risk_cap = config["risk_cap"]
    
    raw_risk_score = cvss_score
    
    # Add enrichment weights based on config
    
    if exploit_available:
        raw_risk_score += weights["exploit_available"]
    if cisa_kev:
        raw_risk_score += weights["cisa_kev"]
    if epss_score >= 0.8:
        raw_risk_score += weights["epss_score_high"]
    elif epss_score >= 0.5:
        raw_risk_score += weights["epss_score_medium"]
        
    # Cap raw risk at configured max
    if raw_risk_score > risk_cap["max_raw_risk_score"]:
        raw_risk_score = risk_cap["max_raw_risk_score"]
        
    # Derived capped 0-10 operational risk score
    risk_score = min(raw_risk_score, risk_cap["max_operational_risk_score"])
    
    # Determine risk band
    risk_band = determine_risk_band(raw_risk_score)
    
    return raw_risk_score, risk_score, risk_band

def determine_risk_band(raw_risk_score):
    if raw_risk_score >= 10:
        return "Critical+"
    elif raw_risk_score >= 8:
        return "High"
    elif raw_risk_score >= 5:
        return "Medium"
    elif raw_risk_score >= 3:
        return "Low"
    else:
        return "Informational"
    
BASE_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_data(cve_id: str, base_url: str = BASE_NVD_URL, cache_dir: str = './nvd_cache', offline_mode: bool = False):
    '''
    !DEPRECATED!
    Funtion to retrieve CVE data from the NIST NVD database.
    
    Args:
        cve_id (str): CVEID to inquire
        base_url (str): hardcorded NIST NVD BaseURL for API - https://services.nvd.nist.gov/rest/json/cves/2.0
        cache_dir (str): directory to cache dataset. Default './nvd_cache'
        
    Returns:
        CVE JSON data from the NIST NVD API
    '''
    # Create a cache directory if it doesn't exist
    os.makedirs(cache_dir, exist_ok=True)
    
    cache_file = os.path.join(cache_dir, f"{cve_id}.json")
    
    # If cached file exist, use it
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            return json.load(f)
     
    
    # Offline mode prevents outbound requests
    if offline_mode:
        log.log.print_warning(f"[Offline Mode] No cache available for {cve_id}, skipping NVD fallback.")
        with open("logs/missed_nvd_fallbacks.log", 'a') as f:
            f.write(f"{cve_id}\n")
        return None
       
    # Otherwise, fetch the data from NVD
    nvd_url = f"{BASE_NVD_URL}?cveID={cve_id.upper()}"
    response = requests.get(nvd_url, allow_redirects=False, timeout=5)
    if response.status_code == 200:
        cve_data = response.json()
        
        # Cache result
        with open(cache_file, 'w') as f:
            json.dump(cve_data, f)
            
        return cve_data
    else:
        log.log.print_error(f"Failed to fetch data for CVE: {cve_id}")
        return None
    
    
def update_enrichment_status(finding):
    if finding.exploit_available or finding.epss_score or finding.cisa_kev:
        finding.enriched = True
    else:
        finding.enriched = False
        
def prefer_vector(vectors):
    order = {"CVSS:3.1": 1, "CVSS:3.0": 2, "CVSS:2.0": 3}
    def rank(v):
        for prefix, score in order.items():
            if v.startswith(prefix):
                return score
        return 99
    return sorted(vectors, key=rank)[0]

def resolve_cvss_vector(scanner_vector: str, auth_cve: str, nvd_cache: dict, current_score: float = 0.0) -> Tuple[str, float]:
    """
    Resolve a CVSS vector for a finding using a priority pipeline:
    1. Use scanner-provided
    2. Fall back to NVD cache vector for auth CVE
    3. If only a base score exists, return scoreonly
    4. Othewise mark as Attempted_NotFound sentinel.
    """
    version = detect_cvss_version(scanner_vector)
    
    # Case 1: Trust scanner vector if valid
    if scanner_vector and version in ("v2", "v3"):
        # If CVSSv3 vector, send it to parser and reconcile score.
        if version == "v3":
            try:
                base_score = parse_cvss_vector(scanner_vector)[0]
            except Exception as e:
                log.log.print_error(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Error parsing CVSS v3 vector '{scanner_vector}': {e}. "
                                    f"Keeping existing score {current_score}")
                log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Using scanner vector without recalculated score: {scanner_vector}")
                return scanner_vector, current_score
            
            if abs(base_score - current_score) > 0.1:
                log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Score mismatch (scanner {base_score} vs stored {current_score}), reconciling...")
                current_score = base_score
            log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Using valid scanner CVSS V3 vector: {scanner_vector}")
            return scanner_vector, current_score
        # v2: Don't feed into CVSS3 Lib - trust scanner score.
        if version == "v2":
            log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL}"
                                  f"Using scanner CVSS v2 vector: {scanner_vector} (score={current_score})")
            #TODO: LAter plug in a CVSS2 Vector parser
            return scanner_vector, current_score
    
    # Case 2: Fallback to NVD
    if nvd_cache and auth_cve:
        nvd_record = nvd_cache.get(auth_cve)
        if nvd_record:
            nvd_vector = nvd_record.get("cvss_vector")
            if nvd_vector and is_valid_cvss_vector(nvd_vector):
                base_score = parse_cvss_vector(nvd_vector)[0]
                log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Using NVD vector for {auth_cve}: {nvd_vector}")
                return nvd_vector, base_score
            
            # Case 3: Score-only fallback
            nvd_score = nvd_record.get("cvss_score")
            if nvd_score is not None:
                log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} No valid vector for {auth_cve}," f"using ScoreOnly sentinel with base score {nvd_score}")
                return f"SENTINEL:ScoreOnly:{nvd_score}", nvd_score
    
    # Case 4: Nothing
    log.log.print_warning(f"[CVSSVector] No CVSS vector available for {auth_cve or 'Unknown'}." " Marking as 'Attempted_NotFound'")
    return "SENTINEL:Attempted_NotFound", current_score

def enrich_scan_results(results: ScanResult, kev_data: Dict[str, bool] = None, epss_data: Dict[str, float] = None, offline_mode: bool = False, nvd_cache: Optional[Any] = None) -> None:
    '''
    Enrich the findings in a ScanResult object with EPSS Score, CISA KEV status, exploit indicators, and recalculate triage priority.
    
    Args:
        results (ScanResult Obj): The parsed vulnerability scan results.
        kev_data (Dict[str, bool], Optional): Mapping of CVE IDs to CISA KEV status.
        epss_data (Dict[str, float], Optional): Mapping of CVE IDs to EPSS Scores.
        offline_mode (Bool): If True, will ignore online fetches for enrichment data pulls.
        nvd_cache (Optional[Any]): Optional parameter, if supplied, will utilize NVD feed cache module for CVE data.
    '''
    miss_logger = EnrichmentMissLogger()
    
    baseline_risk_count = 0
    
    
    kev_data = kev_data or {}
    epss_data = epss_data or {}
    
    enrichment_map = {}
    
     #TODO: DEBUG
    
    for asset in results.assets:
        for finding in asset.findings:
            cisa_hits = []
            epss_scores = []
            enrichment_attempted = False
            enrichment_map.clear()
            if kev_data is not None and epss_data is not None:
                for cve in finding.cves:
                    stats.total_cves += 1
                    enrichment_attempted = True
                    
                    
                    # CISA KEV Enrichment
                    kev_hit = kev_data.get(cve.upper(), False)
                    cisa_hits.append(kev_hit)
                    
                    
                    if kev_hit:
                        stats.kev_hits += 1
                        log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} {cve} found in CISA KEV")
                    else:
                        log.log.logger.warning(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} No CISA KEV record for {cve}.")
                        miss_logger.log_miss(cve, cisa_kev=False, epss_score=None)
                
                    
                    # EPSS Score Enrichment
                    epss_score = epss_data.get(cve)
                    if epss_score is not None:
                        epss_scores.append(epss_score)
                        log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} {cve} EPSS Score: {epss_score}")
                    else:
                        log.log.logger.warning(f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} No EPSS Score for {cve}")
                        epss_scores.append(0.0)
                        stats.epss_misses += 1
                        miss_logger.log_miss(cve, cisa_kev=kev_hit, epss_score=None)
                
                    #TODO: Build small dict of enriched cve info
                    
                    enrichment_map[cve] = {
                        "epss_score": epss_data.get(cve, 0.0),
                        "cisa_kev": kev_data.get(cve.upper(), False),
                        "exploit_available": getattr(finding, "exploit_available", False),
                        "cvss_score": 0.0,
                        "cvss_vector": None
                    }
                    
                    # Fetch nvd_data as secondary source
                    if nvd_cache:
                        nvd_record = nvd_cache.get(cve)
                        if nvd_record:
                            vector = nvd_record.get("cvss_vector")
                            if vector and is_valid_cvss_vector(vector):
                                enrichment_map[cve]["cvss_vector"] = vector
                                enrichment_map[cve]["cvss_score"] = parse_cvss_vector(vector)[0]
                                log.log.logger.debug(f"{Fore.LIGHTMAGENTA_EX}[NVD_Data]{Style.RESET_ALL} CVSS Vector Found in NVD Cache for {cve} - Mapping vector")
                            elif nvd_record.get("cvss_score") is not None:
                                enrichment_map[cve]["cvss_score"] = nvd_record["cvss_score"]
                                log.log.logger.warning(f"{Fore.LIGHTMAGENTA_EX}[NVD_Data]{Style.RESET_ALL} No vector, but base score found for {cve}: {nvd_record['cvss_score']}")
                        else:
                            log.log.logger.warning(f"{Fore.LIGHTMAGENTA_EX}[NVD_Data]{Style.RESET_ALL} No usable CVSS vector found for {cve} in NVD Cache")
                    else:
                        log.log.print_warning(f"{Fore.LIGHTMAGENTA_EX}[NVD_Data]{Style.RESET_ALL} No NVD Cache loaded. NVD Based vector parsing will be unavailable.")
                             
                authoritative_cve = select_authoritative_cve(list(enrichment_map.keys()), enrichment_map)
                
                if authoritative_cve:
                    best = enrichment_map[authoritative_cve]
                    finding.epss_score = best["epss_score"]
                    finding.cisa_kev = best["cisa_kev"] or any(cve_data["cisa_kev"] for cve_data in enrichment_map.values())
                    finding.cvss_vector, finding.cvss_score = resolve_cvss_vector(
                        scanner_vector=finding.cvss_vector,
                        auth_cve=authoritative_cve,
                        nvd_cache=nvd_cache,
                        current_score=finding.cvss_score or 0.0
                    )
                    
                    # Aggregate exploit refs and KEV flag across all CVES
                    kev_flag = False
                    exploit_flag = False
                    
                    for cve, cve_data in enrichment_map.items():
                        if cve_data.get("cisa_kev"):
                            kev_flag = True
                        if cve_data.get("exploit_available"):
                            exploit_flag = True
        
                    finding.exploit_available = bool(finding.exploit_references) or exploit_flag or kev_flag
                    
                    
                    finding.enrichment_source_cve = authoritative_cve
                    log.log.print_info(
                        f"{Fore.LIGHTMAGENTA_EX}[Enrichment]{Style.RESET_ALL} "
                        f"Authoritative CVE: {authoritative_cve} => "
                        f"EPSS={best['epss_score']} | KEV={best['cisa_kev']} | Exploit={finding.exploit_available}"
                    )
                else:
                    log.log.logger.debug(f"[Enrichment] No authoritative CVE selected for Vuln ID: {finding.vuln_id}")
                
            
            # Stats Vector Tracking
            if finding.cvss_vector:
                if finding.cvss_vector.startswith("SENTINEL:"):
                    log.log.logger.debug(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} Skipping validation for sentinel state: "f"{finding.cvss_vector}")
                else:
                    stats.cvss_vectors_assigned += 1
                    stats.cvss_vectors_validated += 1
                    log.log.print_success(f"{Fore.LIGHTMAGENTA_EX}[CVSSVector]{Style.RESET_ALL} "f"Validated vector for {finding.vuln_id}: {finding.cvss_vector}")
                    
                    
                    
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
                epss_score=epss,
                config=config
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
                raw_score=raw_risk_score,
                severity=finding.severity,
                epss_score=epss,
                cisa_kev=finding.cisa_kev,
                exploit_available=finding.exploit_available,
                cfg=triagecfg
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
    log.log.print_info(f"   Total CVEs Processed : {stats.total_cves:,}")
    log.log.print_info(f"   Total CISA KEV Hits : {stats.kev_hits:,}")
    log.log.print_info(f"   Total CVSS Vectors Assigned : {stats.cvss_vectors_assigned:,}")
    log.log.print_info(f"   Total CVSS Vectors Validated : {stats.cvss_vectors_validated:,}")
    log.log.print_info(f"   Total EPSS Misses : {stats.epss_misses:,}")
    log.log.print_info(f"   Total Findings Rx Baseline Risk Adjustment: {baseline_risk_count:,}")
    print(f"{Fore.LIGHTMAGENTA_EX}============[Enrichment Summary End]============{Style.RESET_ALL}")
    
    miss_logger.write_log()