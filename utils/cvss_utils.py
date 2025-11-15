import re
from typing import Optional
from .logger import *
from . import logger_instance as log

try:
    from cvss import CVSS3
except ImportError:
    CVSS3 = None #Fallback if module isn't installed
    
    
CVSS3_REGEX = r'^CVSS:3\.[01]/AV:(N|A|L|P)/AC:(L|H)/PR:(N|L|H)/UI:(N|R)/S:(U|C)/C:(N|L|H)/I:(N|L|H)/A:(N|L|H)$'
CVSS3_REGEX_L = r'CVSS:3\.[0-1]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]'
CVSS2_REGEX = r'^AV:(L|A|N)/AC:(L|M|H)/Au:(N|S|M)/C:(N|P|C)/I:(N|P|C)/A:(N|P|C)$'

CVSS3_RE = re.compile(CVSS3_REGEX)
CVSS2_RE = re.compile(CVSS2_REGEX)

def detect_cvss_version(vector: Optional[str]) -> Optional[str]:
    """Return 'v3', 'v2', or None based on syntax."""
    if not vector:
        return None
    
    v = re.sub(r'\s+', '', vector.strip())
    if v.startswith("SENTINEL:"):
        return None
    
    if CVSS3_RE.match(v):
        return "v3"
    if CVSS2_RE.match(v):
        return "v2"
    return None

def is_valid_cvss_vector(vector: Optional[str]) -> bool:
    '''
    Validate if a given string is well-formed CVSS V3.x or V2 vector.
    
    Args:
        vector (str): CVSS vector string.
        
    Returns:
        bool: True if valid, False otherwise.
    '''
    return detect_cvss_version(vector) in ("v2", "v3")


def parse_cvss_vector(vector: str):
    '''
    Parse a CVSS v3.X vector string into its base score components.
    
    Args:
        vector (str): CVSS vector string.
        
    Returns:
        dict or None: Dictionary of CVSS score or None if invalid or supported.
    '''
    if not is_valid_cvss_vector(vector):
        log.log.print_warning(f"[cvss_util] Invalid CVSS Vector: {vector}")
        return None
    
    if CVSS3 is None:
        raise ImportError("cvss package is not installed. Install it with 'pip install cvss'.")
    
    try:
        cvss_obj = CVSS3(vector)
        return cvss_obj.scores()
    except Exception as e:
        log.log.print_error(f"Error parsing CVSS vector: {e}")
        log.log.logger.exception(f"Exception: {e}")
        return None
