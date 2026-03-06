from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, TYPE_CHECKING, List, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os

from vulnparse_pin.core.classes.scoring_pol import ScoringPolicyV1
from vulnparse_pin.core.classes.pass_classes import DerivedPassResult, Pass
from vulnparse_pin.core.passes.types import ScoreCoverage, ScoredFinding, ScoringPassOutput
from vulnparse_pin.core.classes.pass_classes import PassMeta

if TYPE_CHECKING:
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.core.classes.dataclass import Finding

@dataclass
class ScoringPass(Pass):
    name: str = "Scoring"
    version: str = "1.0"

    def __init__(self, policy: ScoringPolicyV1):
        self.policy = policy
        self._result_lock = threading.Lock()

    def run(self, ctx: "RunContext", scan: "ScanResult") -> "DerivedPassResult":
        """
        Run scoring pass with parallel execution on finding batches.
        Smart caches plugin attributes to avoid repeated getattr() calls.
        """
        # Flatten findings with asset context (asset_id, ip_address)
        findings_with_context: List[Tuple[Any, str, Optional[str]]] = []
        total = 0
        
        for asset in scan.assets:
            for f in asset.findings:
                total += 1
                asset_id = f.asset_id or asset.ip_address
                findings_with_context.append((f, asset_id, asset.ip_address))

        # Pre-compute plugin attributes once (smart caching)
        plugin_cache = self._build_plugin_cache(findings_with_context)

        # Parallel execution for medium+ workloads
        use_parallel = len(findings_with_context) > 100
        
        if use_parallel and (os.cpu_count() or 1) > 1:
            scored_findings, asset_scores = self._score_parallel(
                ctx, findings_with_context, plugin_cache
            )
        else:
            scored_findings, asset_scores = self._score_sequential(
                findings_with_context, plugin_cache
            )

        scored = len(scored_findings)
        coverage_ratio = (scored / total * 1.0) if total else 0.0
        avg_scored = (sum(sf.raw_score for sf in scored_findings.values()) / scored) if scored else None
        avg_op = (sum(sf.operational_score for sf in scored_findings.values()) / scored) if scored else None

        highest_asset: str = None
        highest_score: float = None
        if asset_scores:
            highest_asset = max(asset_scores, key=asset_scores.get)
            highest_score = asset_scores[highest_asset]

        output = ScoringPassOutput(
            scored_findings=scored_findings,
            asset_scores=asset_scores,
            coverage=ScoreCoverage(total_findings=total, scored_findings=scored, coverage_ratio=coverage_ratio),
            highest_risk_asset=highest_asset,
            highest_risk_asset_score=highest_score,
            avg_scored_risk=avg_scored,
            avg_operational_risk=avg_op
        )

        mode_label = "parallel" if use_parallel else "sequential"
        ctx.logger.info(
            "[pass:scoring] %s | scored=%d/%d (%.2f%%)",
            mode_label, scored, total, coverage_ratio,
            extra = {"vp_label": "ScoringPass"}
        )
        
        # Detailed logging to file only
        ctx.logger.debug(
            "[pass:scoring] execution_mode=%s | threads_available=%d | workload=%d findings | cache_size=%d",
            mode_label, os.cpu_count() or 1, len(findings_with_context), len(plugin_cache),
            extra = {"vp_label": "ScoringPass"}
        )

        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Derived risk scoring (truth-preserving)."
        )
        return DerivedPassResult(meta=meta, data=asdict(output))

    def _build_plugin_cache(self, findings_with_context: List[Tuple[Any, str, str]]) -> Dict[str, Dict[str, Any]]:
        """
        Pre-compute plugin attributes once to avoid repeated getattr() calls.
        Secure design: read-only access to findings, no modifications.
        Returns: {finding_id -> {kev, exploit, cvss, epss}}
        """
        cache = {}
        for finding, _, _ in findings_with_context:
            cache[finding.finding_id] = {
                "kev": bool(getattr(finding, "cisa_kev", False)),
                "exploit": bool(getattr(finding, "exploit_available", False)),
                "cvss": getattr(finding, "cvss_score", None),
                "epss": getattr(finding, "epss_score", None),
            }
        return cache

    def _score_sequential(
        self, 
        findings_with_context: List[Tuple[Any, str, str]],
        plugin_cache: Dict[str, Dict[str, Any]]
    ) -> Tuple[Dict[str, ScoredFinding], Dict[str, float]]:
        """Score findings sequentially (fallback or small workloads)."""
        scored_findings: Dict[str, ScoredFinding] = {}
        asset_scores: Dict[str, float] = {}

        for finding, asset_id, _ in findings_with_context:
            attrs = plugin_cache[finding.finding_id]
            sf = self._score_one_cached(finding, asset_id, attrs)
            
            if sf is None:
                continue
            
            scored_findings[sf.finding_id] = sf
            
            if asset_id not in asset_scores or sf.raw_score > asset_scores[asset_id]:
                asset_scores[asset_id] = sf.raw_score

        return scored_findings, asset_scores

    def _score_parallel(
        self,
        ctx: "RunContext",
        findings_with_context: List[Tuple[Any, str, str]],
        plugin_cache: Dict[str, Dict[str, Any]]
    ) -> Tuple[Dict[str, ScoredFinding], Dict[str, float]]:
        """
        Score findings in parallel using ThreadPoolExecutor.
        Thread-safe result aggregation with minimal lock contention.
        """
        # Determine optimal chunk size and worker count
        num_workers = min(len(findings_with_context) // 50 + 1, os.cpu_count() or 1)
        chunk_size = max(1, len(findings_with_context) // num_workers)

        # Split into chunks for parallel processing
        chunks = [
            findings_with_context[i:i + chunk_size]
            for i in range(0, len(findings_with_context), chunk_size)
        ]

        scored_findings: Dict[str, ScoredFinding] = {}
        asset_scores: Dict[str, float] = {}

        # Submit all chunks to executor
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {
                executor.submit(self._score_chunk, chunk, plugin_cache): i
                for i, chunk in enumerate(chunks)
            }

            # Collect results as they complete (not necessarily in order)
            for future in as_completed(futures):
                chunk_results, chunk_assets = future.result()
                
                # Thread-safe merge: acquisition is minimal (insert-only)
                with self._result_lock:
                    scored_findings.update(chunk_results)
                    for asset_id, score in chunk_assets.items():
                        if asset_id not in asset_scores or score > asset_scores[asset_id]:
                            asset_scores[asset_id] = score

        return scored_findings, asset_scores

    def _score_chunk(
        self,
        chunk: List[Tuple[Any, str, str]],
        plugin_cache: Dict[str, Dict[str, Any]]
    ) -> Tuple[Dict[str, ScoredFinding], Dict[str, float]]:
        """
        Score a batch of findings (thread worker function).
        No shared state modification here; returns local results.
        """
        chunk_findings: Dict[str, ScoredFinding] = {}
        chunk_assets: Dict[str, float] = {}

        for finding, asset_id, _ in chunk:
            attrs = plugin_cache[finding.finding_id]
            sf = self._score_one_cached(finding, asset_id, attrs)
            
            if sf is None:
                continue
            
            chunk_findings[sf.finding_id] = sf
            
            # Prefer higher score per asset within this chunk
            if asset_id not in chunk_assets or sf.raw_score > chunk_assets[asset_id]:
                chunk_assets[asset_id] = sf.raw_score

        return chunk_findings, chunk_assets

    def _score_one_cached(
        self,
        f: "Finding",
        asset_id: str,
        attrs: Dict[str, Any]
    ) -> Optional[ScoredFinding]:
        """Score a single finding using pre-cached attributes."""
        pol = self.policy

        kev = attrs["kev"]
        exploit = attrs["exploit"]
        cvss = attrs["cvss"]
        epss = attrs["epss"]

        # Gate: if no enrichment data, no score
        if not kev and not exploit and cvss is None and epss is None:
            return None

        raw = 0.0
        reasons = []

        # CVSS Component (0..10)
        if cvss is not None:
            try:
                c = float(cvss)
                raw += c
                reasons.append(f"cvss={c:.2f}")
            except (TypeError, ValueError):
                pass

        # EPSS Component (0..1.0 | 0..scale), with weights
        if epss is not None:
            try:
                e = float(epss)
                e = min(max(e, pol.epss_min), pol.epss_max)
                e_scaled = e * pol.epss_scale
                
                # Bucket thresholds
                mult = 1.0
                if e >= 0.70:
                    mult = pol.w_epss_high
                    reasons.append(f"epss_high*{pol.w_epss_high:g}")
                elif e >= 0.40:
                    mult = pol.w_epss_medium
                    reasons.append(f"epss_medium*{pol.w_epss_medium:g}")

                raw += e_scaled * mult
                reasons.append(f"epss={e:.5f}({e_scaled:.2f})")
            except (TypeError, ValueError):
                pass

        # KEV Component
        if kev:
            raw += pol.kev_evd * pol.w_kev
            reasons.append("KEV Present")

        # Exploit Component
        if exploit:
            raw += pol.exploit_evd * pol.w_exploit
            reasons.append("Exploit Available")

        score = (raw / pol.max_raw_risk) * pol.max_op_risk
        score = max(0.0, min(score, pol.max_op_risk))
        band = self._band(raw)

        return ScoredFinding(
            finding_id=f.finding_id,
            asset_id=asset_id,
            raw_score=round(raw, 4),
            operational_score=round(score, 4),
            risk_band=band,
            reason=";".join(reasons)
        )

    def _score_one(self, f: "Finding") -> Optional[ScoredFinding]:
        """
        Legacy method for backward compatibility.
        Kept for tests and external callers; uses cached scoring internally.
        """
        attrs = {
            "kev": bool(getattr(f, "cisa_kev", False)),
            "exploit": bool(getattr(f, "exploit_available", False)),
            "cvss": getattr(f, "cvss_score", None),
            "epss": getattr(f, "epss_score", None),
        }
        asset_id = f.asset_id or "SENTINEL:AssetID_Missing"
        return self._score_one_cached(f, asset_id, attrs)

    def _band(self, score: float) -> str:
        pol = self.policy
        if score >= pol.band_critical:
            return "Critical"
        if score >= pol.band_high:
            return "High"
        if score >= pol.band_medium:
            return "Medium"
        if score >= pol.band_low:
            return "Low"
        return "Informational"
