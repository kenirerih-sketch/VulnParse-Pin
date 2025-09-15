from parsers.nessus_parser import NessusParser
from parsers.nessusXML_parser import NessusXMLParser
from parsers.openvas_parser import OpenVASParser
from parsers.openvasXML_parser import OpenVASXMLParser

def detect_parser(filepath: str):
    filepath = str(filepath).lower()
    
    # --- JSON First ---
    if filepath.endswith(".json"):
        with open(filepath, 'r', encoding='utf-8') as f:
            head = f.read(500)
            
        # Crude-style detection: Check for nessus json and openvas unique fields
        if "plugin_id" in head or "plugin_name" in head:
            return NessusParser(filepath)