import os
import yaml
import utils.logger_instance as log

def load_config(path: str = "nvd_config.yaml") -> dict:
    """
    Load YAML NVD config file for VulnParse-Pin.
    
    Args:
        path (str): Path to the config file (default: nvd_config.yaml)
        
    Returns:
        dict: Config Dict, empty if file not found or invalid
    """
    
    real_path = os.path.join(os.path.dirname(__file__), "..", "config", path)
    real_path = os.path.abspath(real_path)
    
    if not os.path.exists(real_path):
        log.log.print_warning(f"[Config] No config file found at {path}, using defaults.")
        return {}
    
    try:
        with open(real_path, "r", encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}
            log.log.logger.debug(f"[Config] Loaded config from {real_path}")
            return config
    except yaml.YAMLError as e:
        log.log.logger.exception(f"[Config]Error parsing YAML file {real_path}: {e}")
        return {}
    except Exception as e:
        log.log.logger.exception(f"[Config] Unexpected error loading {real_path}: {e}")
        return {}
    