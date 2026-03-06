# VulnParse-Pin – Vulnerability Parsing and Triage Engine
# Copyright (C) 2025 Shade216

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# any later version.
# See the LICENSE file for full terms.
from __future__ import annotations
import gzip
import json
from datetime import datetime
import re
import io
import threading
import concurrent.futures, os
from typing import Any, Dict, List, TYPE_CHECKING, Optional, Set
try:
    import ijson
except ImportError as exc:
    ijson = None
    print(f"ijson dependency is missing; for runtime optimization, install ijson 'pip install ijson': {exc}")

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext

_YEAR_KEY_RE = re.compile(r"^nvd\.year\.(\d{4})$")

class NVDFeedCache:
    '''
    Feed-based NVD Cache.
    - Pulls feed list + TTL policy from config.yaml
    - Uses FeedCacheManager for caching/integrity/refresh/offline
    - Parses cached raw .json.gz feeds into in-memory lookup for O(1) enrichment
    '''

    def __init__(self, ctx: "RunContext") -> None:
        self.ctx = ctx
        self.lookup: Dict[str, Dict[str, Any]] = {}
        self.target_cves: Optional[Set[str]] = None  # CVEs to index (if filtering)
        # lock to protect lookup when parsing in parallel
        self._lock = threading.Lock()

    def refresh(self, *, config: dict, feed_cache, refresh_cache: bool, offline: bool, years: Optional[Set[int]] = None, include_modified: bool = True, target_cves: Optional[Set[str]] = None) -> None:
        feeds = nvd_feed_plan(config)

        if not feeds:
            self.ctx.logger.print_info("NVD disabled via config.")
            return

        if years is not None:
            feeds = self._filter_feeds_by_years(feeds, years, include_modified=include_modified)
            if not feeds:
                self.ctx.logger.info("Enabled, but no feeds selected by plan; skipping...", extra={"vp_label": "NVD Feed Loader"})
                return

        missing: List[str] = []
        self.target_cves = target_cves

        if target_cves:
            self.ctx.logger.debug(
                f"NVD index filtered to {len(target_cves)} CVEs from scan",
                extra={"vp_label": "NVD Optimization"}
            )

        # first resolve all feed paths so that we can handle missing ones
        resolved_paths: List[str] = []
        for f in feeds:
            try:
                path = feed_cache.resolve_nvd_feed(
                    key=f["key"],
                    ttl_hours=int(f["ttl_hours"]),
                    refresh_cache=refresh_cache,
                    offline=offline,
                )
            except FileNotFoundError:
                missing.append(f["fname"])
                continue
            resolved_paths.append(path)

        # parse each path; use threads when there is more than one to reduce wall time
        if resolved_paths:
            if len(resolved_paths) > 1:
                max_workers = min(len(resolved_paths), os.cpu_count() or 1)
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = {pool.submit(self._parse_feed, p): p for p in resolved_paths}
                    for fut in concurrent.futures.as_completed(futures):
                        # propagate exceptions
                        fut.result()
            else:
                self._parse_feed(resolved_paths[0])

        if offline and missing:
            self.ctx.logger.warning(
                f"Offline mode: {len(missing)} feed(s) missing: {', '.join(missing)}."
            )
    # NOTE(perf): NVD feed parse builds in-mem O(1) index at startup.
    # Uses ijson streaming to parse one CVE at a time (no full load into RAM).
    # With target_cves filtering, only parses CVEs needed by the scan.
    def _parse_feed(self, path: str) -> None:
        """Parse NVD 2.0 feed into lookup dict with streaming and optional CVE filtering."""
        ctx = self.ctx
        parsed_count = 0
        skipped_count = 0

        # Determine if this feed is year-specific so we can fast-skip
        year = None
        path_str = str(path)
        m = re.search(r"year\.(\d{4})", path_str)
        if m:
            try:
                year = int(m.group(1))
            except ValueError:
                year = None

        # Compute remaining targets for this feed (used for early termination)
        remaining: Optional[Set[str]] = None
        if self.target_cves is not None:
            if year is not None:
                prefix = f"CVE-{year}-"
                remaining = {c for c in self.target_cves if c.startswith(prefix)}
                if not remaining:
                    # nothing to index in this year's file
                    ctx.logger.debug(
                        f"Skipping {year} feed; no CVEs from scan match this year.",
                        extra={"vp_label": "NVD Optimization"}
                    )
                    return
            else:
                # modified feed: we need to look for any remaining CVEs
                remaining = set(self.target_cves)

        # open_for_read already validates path; suppress redundant log message
        with ctx.pfh.open_for_read(path, mode="rb", label="NVD Feed (.json.gz)", log=False) as raw:
            # Open gzip in binary mode for ijson efficiency
            with gzip.open(raw, mode="rb") as f:
                # Use ijson for streaming if available, fallback to json.load
                if ijson is not None:
                    vulnerabilities = ijson.items(f, "vulnerabilities.item")
                else:
                    text_f = io.TextIOWrapper(f, encoding="utf-8")
                    data = json.load(text_f)
                    vulnerabilities = data.get("vulnerabilities", [])

                # Parse pertinent information from feeds.
                for item in vulnerabilities:
                    cve = (item or {}).get("cve", {}) or {}
                    cve_id = cve.get("id")
                    if not cve_id:
                        continue

                    # Early exit: skip if filtering and CVE not in target set
                    if self.target_cves is not None and cve_id not in self.target_cves:
                        skipped_count += 1
                    else:
                        parsed_count += 1

                        # Description
                        desc = ""
                        descs = cve.get("descriptions") or []
                        if descs:
                            desc = (descs[0] or {}).get("value", "") or ""
                        # Published/lastMod
                        published = cve.get("published")
                        last_mod = cve.get("lastModified")
                        # CVSS Metrics
                        metrics = cve.get("metrics", {}) or {}
                        cvss, vector = None, None
                        # Break out CVSS Version Prioritization
                        if "cvssMetricV31" in metrics:
                            cvss, vector = self._choose_cvss(metrics["cvssMetricV31"])
                        elif "cvssMetricV30" in metrics:
                            cvss, vector = self._choose_cvss(metrics["cvssMetricV30"])
                        elif "cvssMetricV2" in metrics:
                            cvss, vector = self._choose_cvss(metrics["cvssMetricV2"])

                        # Create O(1) Lookup (thread-safe)
                        with self._lock:
                            self.lookup[cve_id] = {
                                "id": cve_id,
                                "description": desc,
                                "cvss_score": cvss,
                                "cvss_vector": vector,
                                "published": published,
                                "last_modified": last_mod,
                            }

                        if remaining is not None and cve_id in remaining:
                            remaining.remove(cve_id)
                            if not remaining:
                                ctx.logger.debug(
                                    f"Early termination: all target CVEs for {'year ' + str(year) if year else 'modified feed'} indexed after {parsed_count + skipped_count} items",
                                    extra={"vp_label": "NVD Optimization"}
                                )
                                break

        # Log parse statistics
        if self.target_cves is not None and skipped_count > 0:
            ctx.logger.debug(
                f"NVD parse: indexed {parsed_count} CVEs, skipped {skipped_count} (not in scan)",
                extra={"vp_label": "NVD Optimization"}
            )

    def _choose_cvss(self, metrics_list) -> tuple | tuple[None, None]:
        """Pick Primary cvss first, fallback to Secondary."""
        primary = next((m for m in metrics_list if m.get("type") == "Primary"), None)
        if not primary and metrics_list:
            primary = metrics_list[0]
        if primary and "cvssData" in primary:
            d = primary["cvssData"]
            return d.get("baseScore"), d.get("vectorString")
        return None, None

    def get(self, cve_id: str) -> dict[str, Any]:
        """Lookup CVE from cache.
        Always return a normalized dict with expected keys, even if the CVE is missing
        (values default to None).
        """

        default_record = {
        "id": cve_id,
        "description": "",
        "cvss_score": None,
        "cvss_vector": None,
        "published": None,
        "last_Modified": None,
        "found": False,
        }

        record = self.lookup.get(cve_id, {})
        if record is None:
            return default_record

        merged = {**default_record, **record}
        merged["found"] = True
        return merged

    def _filter_feeds_by_years(self, feeds: List[Dict], years: Set[int], *, include_modified: bool) -> List[Dict]:
        output: List[Dict] = []
        for f in feeds:
            key = str(f.get("key", ""))

            if key == "nvd.modified":
                if include_modified:
                    output.append(f)
                continue

            m = _YEAR_KEY_RE.match(key)
            if m and int(m.group(1)) in years:
                output.append(f)

        return output

def _cfg_get(config: Dict[str, Any], path: List[str], default = None):
    cur = config
    for k in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur

def _cfg_int(config: Dict[str, Any], path: List[str], default: int) -> int:
    v = _cfg_get(config, path, default)
    try:
        return int(v)
    except Exception:
        return default

def _cfg_bool(config: Dict[str, Any], path: List[str], default: bool) -> bool:
    v = _cfg_get(config, path, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y", "on")
    return default

def nvd_policy_from_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pulls NVD policy config values from the config.
    """
    enabled = _cfg_bool(config, ["feed_cache", "nvd", "enabled"], True)

    ttl_default = _cfg_int(config, ["feed_cache", "defaults", "ttl_hours"], 24)
    ttl_yearly = _cfg_int(config, ["feed_cache", "ttl_hours", "nvd_yearly"], ttl_default)
    ttl_modified = _cfg_int(config, ["feed_cache", "ttl_hours", "nvd_modified"], min(2, ttl_default))


    now_year = datetime.now().year
    start_year = _cfg_int(config, ["feed_cache", "nvd", "start_year"], now_year)
    end_year = _cfg_int(config, ["feed_cache", "nvd", "end_year"], now_year)


    if start_year > end_year:
        start_year, end_year = end_year, start_year
    if end_year > now_year:
        end_year = now_year

    return {
        "enabled": enabled,
        "ttl_default": ttl_default,
        "ttl_yearly": ttl_yearly,
        "ttl_modified": ttl_modified,
        "start_year": start_year,
        "end_year": end_year,
    }

def nvd_feed_plan(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Returns the NVD Feed plan based off the YAML config parameters.

    :param config: Global config YAML
    :type config: Dict[str, Any]
    :return: A list of nvd feed params based on YAML config.
    :rtype: List[Dict[str, Any]]
    """
    p = nvd_policy_from_config(config)
    if not p["enabled"]:
        return []

    feeds = [{
        "key": "nvd.modified",
        "fname": "modified.json.gz",
        "ttl_hours": p["ttl_modified"],
    }]

    for y in range(p["start_year"], p["end_year"] + 1):
        feeds.append({
            "key": f"nvd.year.{y}",
            "fname": f"{y}.json.gz",
            "ttl_hours": p["ttl_yearly"],
        })

    return feeds
