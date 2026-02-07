# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
#  any later version.
# See the LICENSE file for full terms.

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