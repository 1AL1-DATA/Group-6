"""
Aggregator and Report Generator
Combines findings from all analysis stages
"""
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}


@dataclass
class AggregatedFinding:
    """Final finding after aggregation."""
    finding_type: str
    severity: str
    evidence: str
    line: int
    file: str
    sources: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    needs_escalation: bool = False
    llm_explanation: Optional[str] = None
    fix_suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "evidence_span": self.evidence,
            "line": self.line,
            "file": self.file,
            "risk_score": round(self.risk_score, 2),
            "needs_escalation": self.needs_escalation,
            "llm_explanation": self.llm_explanation,
            "fix_suggestion": self.fix_suggestion,
            "source_details": self.sources
        }


class Reporter:
    """Aggregates and generates reports."""
    
    def __init__(self):
        pass
    
    def aggregate(
        self,
        rule_findings: List[Any],
        heuristic_findings: List[Any],
        risk_scores: List[Any],
        llm_analyses: List[Any],
        file_path: str
    ) -> List[AggregatedFinding]:
        """
        Aggregate findings from all sources.
        
        Args:
            rule_findings: Findings from rules engine
            heuristic_findings: Findings from heuristic analyzer
            risk_scores: Risk scores
            llm_analyses: LLM analyses
            file_path: File being analyzed
            
        Returns:
            List of aggregated findings
        """
        all_findings = []
        seen = set()
        
        # Process rule findings
        for f in rule_findings:
            key = (f.line, f.finding_type)
            if key in seen:
                continue
            seen.add(key)
            
            finding = AggregatedFinding(
                finding_type=f.finding_type,
                severity=f.severity,
                evidence=f.evidence,
                line=f.line,
                file=file_path,
                sources=[f.to_dict()],
                needs_escalation=f.needs_escalation
            )
            all_findings.append(finding)
        
        # Process heuristic findings
        for f in heuristic_findings:
            key = (f.line, f.finding_type)
            if key in seen:
                # Merge with existing
                for existing in all_findings:
                    if existing.line == f.line and existing.finding_type == f.finding_type:
                        existing.sources.append(f.to_dict())
                        if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(existing.severity, 0):
                            existing.severity = f.severity
                        break
            else:
                seen.add(key)
                finding = AggregatedFinding(
                    finding_type=f.finding_type,
                    severity=f.severity,
                    evidence=f.evidence,
                    line=f.line,
                    file=file_path,
                    sources=[f.to_dict()]
                )
                all_findings.append(finding)
        
        # Add risk scores
        for score in risk_scores:
            for finding in all_findings:
                if finding.line == score.line:
                    finding.risk_score = score.score
                    break
        
        # Add LLM analyses
        for analysis in llm_analyses:
            for finding in all_findings:
                if finding.line == analysis.line:
                    finding.llm_explanation = analysis.explanation
                    finding.fix_suggestion = analysis.fix_suggestion
                    break
        
        # Sort by severity
        all_findings.sort(
            key=lambda x: (SEVERITY_ORDER.get(x.severity, 0), x.line),
            reverse=True
        )
        
        return all_findings
    
    def generate_report(
        self,
        findings: List[AggregatedFinding],
        file_count: int,
        scan_time: float
    ) -> Dict[str, Any]:
        """
        Generate final report.
        
        Args:
            findings: Aggregated findings
            file_count: Number of files scanned
            scan_time: Scan duration in seconds
            
        Returns:
            Report dictionary
        """
        summary = {
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f.severity == "Critical"),
            "high_count": sum(1 for f in findings if f.severity == "High"),
            "medium_count": sum(1 for f in findings if f.severity == "Medium"),
            "low_count": sum(1 for f in findings if f.severity == "Low"),
            "files_scanned": file_count,
            "scan_time_seconds": round(scan_time, 2)
        }
        
        return {
            "summary": summary,
            "findings": [f.to_dict() for f in findings]
        }
    
    def print_report(self, report: Dict[str, Any]) -> None:
        """Print human-readable report."""
        print("\n" + "=" * 60)
        print(" RepoGuard Security Report")
        print("=" * 60)
        
        summary = report.get("summary", {})
        print(f"\nFiles Scanned: {summary.get('files_scanned', 0)}")
        print(f"Scan Time: {summary.get('scan_time_seconds', 0)}s")
        print(f"\nFindings: {summary.get('total_findings', 0)}")
        print(f"  Critical: {summary.get('critical_count', 0)}")
        print(f"  High: {summary.get('high_count', 0)}")
        print(f"  Medium: {summary.get('medium_count', 0)}")
        print(f"  Low: {summary.get('low_count', 0)}")
        
        findings = report.get("findings", [])
        if findings:
            print("\n" + "-" * 60)
            for i, f in enumerate(findings[:20], 1):
                print(f"\n{i}. [{f['severity']}] {f['finding_type']}")
                print(f"   File: {f['file']}:{f['line']}")
                print(f"   Evidence: {f['evidence_span'][:60]}")
                if f.get('llm_explanation'):
                    print(f"   Explanation: {f['llm_explanation'][:100]}...")
                if f.get('fix_suggestion'):
                    print(f"   Fix: {f['fix_suggestion'][:80]}...")
        
        print("\n" + "=" * 60)


if __name__ == "__main__":
    reporter = Reporter()
    print("Reporter test ready")