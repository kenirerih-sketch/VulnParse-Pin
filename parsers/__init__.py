from .nessus_parser import NessusParser
from .openvas_parser import OpenVASParser

parsers = [
    NessusParser(),
    OpenVASParser(), 
    #Rapid7Parser() etc
]
