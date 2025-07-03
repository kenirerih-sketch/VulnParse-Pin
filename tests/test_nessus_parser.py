from logging import Logger
from tabnanny import verbose
import pytest
from parsers.nessus_parser import NessusParser
from classes.dataclass import ScanResult, Asset
from utils.logger import LoggerWrapper

@pytest.fixture(scope='session', autouse=True)
def setup_logging():
    import utils.logger_instance as log
    if not getattr(log, 'log', None):
        log.log = LoggerWrapper(log_file='logs/pytest.log')
        log.log.print_info("Pytest logging initialized.")

@pytest.fixture
def nessus_sample_report():
    return {
        "scan": {
            "info": {
                "name": "Internal Scan",
                "start_time": "2025-07-03T12:00:00Z",
                "end time": "2025-07--03T16:00:00Z"
            },
            "hosts": [
                {
                    "hostname": "test-host",
                    "ip": "192.168.1.1",
                    "vulnerabilities": [
                        {
                            "plugin_id": "1000",
                            "plugin_name": "test-vuln",
                            "severity": "High",
                            "cvss_base_score": 7.5,
                            "cve": ["CVE-2023-12345"]
                        }
                    ]
                }
            ]
        }
    }
    
def test_nessus_parser_basic(nessus_sample_report):
    parser = NessusParser()
    scan_result = parser.parse(nessus_sample_report)
    
    assert isinstance(scan_result, ScanResult)
    assert len(scan_result.assets) == 1
    asset = scan_result.assets[0]
    assert isinstance(asset, Asset)
    assert asset.hostname == "test-host"
    assert asset.ip_address == "192.168.1.1"
    assert len(asset.findings) == 1
    vuln = asset.findings[0]
    assert vuln.cves == ["CVE-2023-12345"]
    assert vuln.cvss_score == 7.5