from colorama import init, Fore, Style
import logging
import os
import json

init(autoreset=True)

class LoggerWrapper:
    def __init__(self, log_file, log_level="INFO"):
        self.logger = logging.getLogger('vulnparse')
        self.logger.setLevel(getattr(logging, log_level.upper(), "INFO"))
        
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        
    def print_info(self, msg):
        print(f"{Fore.LIGHTCYAN_EX}[INFO] [*]{Style.RESET_ALL} {msg}")
        self.logger.info(msg)
        
    def print_success(self, msg):
        print(f"{Fore.LIGHTGREEN_EX}[SUCCESS] [+]{Style.RESET_ALL} {msg}")
        self.logger.info(msg)
        
    def print_warning(self, msg):
        print(f"{Fore.YELLOW}[WARNING] [!]{Style.RESET_ALL} {msg}")
        self.logger.warning(msg)
        
    def print_error(self, msg):
        print(f"{Fore.RED}[ERROR] [-]{Style.RESET_ALL} {msg}")
        self.logger.error(msg)
        
class EnrichmentMissLogger:
    def __init__(self, log_file="logs/missed_enrichments.json"):
        self.log_file = log_file
        self.misses = {}
        
        # Create log directory if it doesn't exist.
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
    def log_miss(self, cve_id, cisa_kev=False, epss_score=None):
        if cve_id not in self.misses:
            self.misses[cve_id] = {
                "cisa_kev": cisa_kev,
                "epss_score": epss_score
            }
    
    def write_log(self):
        with open(self.log_file, "w") as f:
            json.dump(self.misses, f, indent=4)


