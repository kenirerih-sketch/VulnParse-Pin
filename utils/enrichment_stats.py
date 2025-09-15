class EnrichmentStats:
    def __init__(self):
        self.total_cves = 0
        self.kev_hits = 0
        self.epss_misses = 0
        self.cvss_vectors_assigned = 0
        self.cvss_vectors_validated = 0
        self.exploitdb_hits = 0
        
    def reset(self):
        self.__init__()

# Instance
stats = EnrichmentStats()