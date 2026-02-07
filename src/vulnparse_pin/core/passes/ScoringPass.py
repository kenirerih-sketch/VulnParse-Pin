from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any, Optional, TYPE_CHECKING


if TYPE_CHECKING:
    from vulnparse_pin.core.classes.pass_classes import DerivedPassResult
    from vulnparse_pin.core.classes.dataclass import RunContext, ScanResult
    from vulnparse_pin.core.classes.dataclass import Finding
    from vulnparse_pin.core.passes.types import ScoreCoverage, ScoredFinding, ScoringPassOutput
    from vulnparse_pin.core.classes.pass_classes import PassMeta

@dataclass
class ScoringPass:
    name: str = "Scoring"
    version: str = "1.0"


    def run(self, ctx: "RunContext", scan: "ScanResult") -> "DerivedPassResult":
        total = 0
        scored = 0


        scored_findings = Dict[str, ScoredFinding] = {}
        asset_scores = Dict[str, float] = {}


        for asset in scan.assets:
            best_asset: Optional[float] = None
            aid = None # Prefer f.assset_id or fallback to asset.ip_address

            for f in asset.findings:
                total += 1
                if aid is None:
                    aid = f.asset_id or asset.ip_address

                sf = self._score_one(f)
                if sf is None:
                    continue


                scored += 1
                scored_findings[f.finding_id] = sf
                
                if best_asset is None or sf.score > best_asset:
                    best_asset = sf.score

            if best_asset is not None and aid is not None:
                asset_scores[aid] = best_asset
                
        
        coverage_pct = (scored / total * 100.0) if total else 0.0
        avg_scored = (sum(sf.score for sf in scored_findings.values()) / scored) if scored else None
        
        
        highest_asset = None
        highest_score = None
        if asset_scores:
            highest_asset = max(asset_scores, key=asset_scores.get)
            highest_score = asset_scores[highest_asset]
        
        output = ScoringPassOutput(
            scored_findings=scored_findings,
            asset_scores=asset_scores,
            coverage=ScoreCoverage(total_findings=total, scored_findings=scored, coverage_pct=coverage_pct),
            highest_risk_asset=highest_asset,
            highest_risk_asset_score=highest_score,
            avg_scored_risk=avg_scored
        )
        
        ctx.logger.info(
            "[pass:scoring] scored=%d/%d (%.2f%%)",
            scored, total, coverage_pct,
            extra = {"vp_label": "ScoringPass"}
        )
        
        meta = PassMeta(
            name=self.name,
            version=self.version,
            created_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            notes="Derived risk scoring (truth-preserving)."
        )
        return DerivedPassResult(meta=meta, data=output)
    
    def _score_one(self, f: "Finding") -> Optional[ScoredFinding]:
        kev = bool(getattr(f, "cisa_kev", False))
        exploit = bool(getattr(f, "exploit_available", False))
        cvss = getattr(f, "cvss_score", None)
        epss = getattr(f, "epss_score", None)
        
        # Gate
        if not kev and not exploit and cvss is None and epss is None:
            return None
        
        
        raw = 0.0
        reasons = []
        
        # Compile Scoring Signals
        if cvss is not None:
            try:
                raw = max(raw, float(cvss))
                reasons.append(f"cvss={cvss}")
            except (TypeError, ValueError):
                pass
        
        if epss is not None:
            try:
                raw = max(raw, float(epss) * 10.0)
                reasons.append(f"epss={epss}")
            except (TypeError, ValueError):
                pass
        
        if kev:
            raw = max(raw, 9.5)
            reasons.append("KEV Present")
        
        if exploit:
            raw = max(raw, 9.0)
            reasons.append("Exploit Available")
        
        
        score = min(max(raw, 0.0), 10.0)
        band = self._band(score)
        
        return ScoredFinding(
            finding_id=f.finding_id,
            asset_id=f.asset_id or "SENTINEL:AssetID_Missing",
            raw_score=raw,
            score=score,
            risk_band=band,
            reason=";".join(reasons)
        )
    
    def _band(self, score: float) -> str:
        if score >= 8.9:
            return "Critical"
        if score >= 6.9:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score >= 2.0:
            return "Low"
        return "Informational"
