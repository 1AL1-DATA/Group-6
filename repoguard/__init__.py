"""
RepoGuard - Hybrid LLM-based Security Review Tool
Main entry point for analysis
"""
import logging
import time
from typing import List, Dict, Any, Optional

from .engine.rules_engine import RulesEngine
from .engine.heuristic_analyzer import HeuristicAnalyzer
from .engine.context_analyzer import ContextValidator
from .models.risk_scorer import RiskScorer
from .models.llm_analyzer import LLMAnalyzer
from .engine.aggregator import Reporter, AggregatedFinding
from .utils.repo_traverser import RepositoryTraverser


logger = logging.getLogger(__name__)


class RepoGuard:
    """
    Main RepoGuard analyzer.
    Orchestrates multi-stage analysis pipeline.
"""
    
    def __init__(
        self,
        rules_path: Optional[str] = None,
        use_llm: bool = False,
        llm_model: str = "llama3.2",
        llm_api_base: Optional[str] = None,
        reduce_false_positives: bool = True,
        export_prompts: Optional[str] = None
    ):
        """
        Initialize RepoGuard.
        
        Args:
            rules_path: Optional custom rules file
            use_llm: Whether to use LLM for analysis
            llm_model: LLM model name
            llm_api_base: Custom LLM API URL (default: http://localhost:11434)
            reduce_false_positives: Use context-aware validation
            export_prompts: Export prompts to file for external LLM processing
        """
        self.traverser = RepositoryTraverser()
        self.rules_engine = RulesEngine(rules_path)
        self.heuristic = HeuristicAnalyzer()
        self.risk_scorer = RiskScorer()
        self.context_validator = ContextValidator() if reduce_false_positives else None
        self.llm_analyzer = None
        self.reduce_false_positives = reduce_false_positives
        
        if use_llm:
            self.llm_analyzer = LLMAnalyzer(
                model=llm_model,
                api_base=llm_api_base or "http://localhost:11434",
                export_prompts=export_prompts
            )
            
        self.reporter = Reporter()
        logger.info("RepoGuard initialized")
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """
        Scan an entire repository.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            Security report
        """
        start_time = time.time()
        
        # Get files to scan
        files = self.traverser.traverse(repo_path)
        all_findings: List[AggregatedFinding] = []
        
        # Scan each file
        for file_info in files:
            file_path = file_info['path']
            content = file_info['content']
            
            logger.info(f"Scanning {file_path}...")
            
            # Stage 1: Rules
            rule_findings = self.rules_engine.scan(content, file_path)
            
            # Stage 2: Heuristics
            heuristic_findings = self.heuristic.analyze(content, file_path)
            
            # Aggregate findings for risk scoring
            all_finding_dicts = []
            for f in rule_findings:
                all_finding_dicts.append({
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "evidence_span": f.evidence,
                    "line": f.line,
                    "needs_escalation": f.needs_escalation
                })
            for f in heuristic_findings:
                all_finding_dicts.append({
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "evidence_span": f.evidence,
                    "line": f.line,
                    "needs_escalation": False
                })
            
            # Stage 3: Risk Scoring
            risk_scores = self.risk_scorer.score_findings(all_finding_dicts, content)
            score_map = {s.line: s.score for s in risk_scores}
            
            # Stage 4: LLM (selective escalation)
            llm_analyses = []
            if self.llm_analyzer and self.llm_analyzer.is_available():
                for f in all_finding_dicts:
                    risk_score = score_map.get(f.get("line", 0), 0.5)
                    if self.risk_scorer.should_escalate(
                        risk_score,
                        0.5,
                        f.get("needs_escalation", False)
                    ):
                        analysis = self.llm_analyzer.analyze(f, content)
                        llm_analyses.append(analysis)
            
            # Aggregate
            findings = self.reporter.aggregate(
                rule_findings,
                heuristic_findings,
                risk_scores,
                llm_analyses,
                file_path
            )
            all_findings.extend(findings)
        
        # Generate report
        scan_time = time.time() - start_time
        report = self.reporter.generate_report(
            all_findings,
            len(files),
            scan_time
        )
        
        logger.info(f"Scan complete: {report['summary']['total_findings']} findings")
        return report
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Security report for file
        """
        start_time = time.time()
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Run all stages
        rule_findings = self.rules_engine.scan(content, file_path)
        heuristic_findings = self.heuristic.analyze(content, file_path)
        
        all_finding_dicts = []
        for f in rule_findings:
            all_finding_dicts.append({
                "finding_type": f.finding_type,
                "severity": f.severity,
                "evidence_span": f.evidence,
                "line": f.line,
                "needs_escalation": f.needs_escalation
            })
        for f in heuristic_findings:
            all_finding_dicts.append({
                "finding_type": f.finding_type,
                "severity": f.severity,
                "evidence_span": f.evidence,
                "line": f.line,
                "needs_escalation": False
            })
        
        risk_scores = self.risk_scorer.score_findings(all_finding_dicts, content)
        
        # Map findings to risk scores
        score_map = {s.line: s.score for s in risk_scores}
        
        llm_analyses = []
        if self.llm_analyzer and self.llm_analyzer.is_available():
            for f in all_finding_dicts:
                risk_score = score_map.get(f.get("line", 0), 0.5)
                if self.risk_scorer.should_escalate(
                    risk_score,
                    0.5,
                    f.get("needs_escalation", False)
                ):
                    analysis = self.llm_analyzer.analyze(f, content)
                    llm_analyses.append(analysis)
        
        findings = self.reporter.aggregate(
            rule_findings,
            heuristic_findings,
            risk_scores,
            llm_analyses,
            file_path
        )
        
        scan_time = time.time() - start_time
        return self.reporter.generate_report(findings, 1, scan_time)
    
    def scan_code(self, code: str, filename: str = "code.py") -> Dict[str, Any]:
        """
        Scan code string directly.
        
        Args:
            code: Code content
            filename: Virtual filename
            
        Returns:
            Security report
        """
        start_time = time.time()
        
        rule_findings = self.rules_engine.scan(code, filename)
        heuristic_findings = self.heuristic.analyze(code, filename)
        
        all_finding_dicts = []
        for f in rule_findings:
            all_finding_dicts.append({
                "finding_type": f.finding_type,
                "severity": f.severity,
                "evidence_span": f.evidence,
                "line": f.line,
                "needs_escalation": f.needs_escalation
            })
        for f in heuristic_findings:
            all_finding_dicts.append({
                "finding_type": f.finding_type,
                "severity": f.severity,
                "evidence_span": f.evidence,
                "line": f.line,
                "needs_escalation": False
            })
        
        risk_scores = self.risk_scorer.score_findings(all_finding_dicts, code)
        score_map = {s.line: s.score for s in risk_scores}
        
        # Filter false positives using context analysis
        if self.context_validator:
            filtered_findings = []
            for f in all_finding_dicts:
                is_vuln, confidence, reasons = self.context_validator.validate(
                    f.get("finding_type", ""),
                    f.get("evidence_span", ""),
                    code,
                    ""
                )
                if is_vuln:
                    f["context_confidence"] = confidence
                    f["context_reasons"] = reasons
                    filtered_findings.append(f)
                else:
                    logger.debug(f"Filtered false positive: {f.get('finding_type')} at line {f.get('line')} - {reasons}")
            all_finding_dicts = filtered_findings
        
        llm_analyses = []
        if self.llm_analyzer and self.llm_analyzer.is_available():
            for f in all_finding_dicts:
                risk_score = score_map.get(f.get("line", 0), 0.5)
                if self.risk_scorer.should_escalate(
                    risk_score,
                    0.5,
                    f.get("needs_escalation", False)
                ):
                    analysis = self.llm_analyzer.analyze(f, content)
                    llm_analyses.append(analysis)
        
        findings = self.reporter.aggregate(
            rule_findings,
            heuristic_findings,
            risk_scores,
            llm_analyses,
            filename
        )
        
        scan_time = time.time() - start_time
        return self.reporter.generate_report(findings, 1, scan_time)


# MCP entry point
def analyze_file(file_path: str, file_content: str) -> Dict[str, Any]:
    """
    MCP-compatible entry point.
    
    Args:
        file_path: Path to file
        file_content: Content (unused, file is read directly)
        
    Returns:
        Analysis report
    """
    guard = RepoGuard()
    return guard.scan_file(file_path)


def analyze_code(code: str, filename: str = "code.py") -> Dict[str, Any]:
    """
    MCP-compatible entry point for code string.
    
    Args:
        code: Code content
        filename: Filename
        
    Returns:
        Analysis report
    """
    guard = RepoGuard()
    return guard.scan_code(code, filename)


def main():
    """CLI entry point."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: repoguard <command> [options]")
        print("  scan <path>   - Scan repository or file")
        sys.exit(1)
        
    command = sys.argv[1]
    
    if command == "scan":
        path = sys.argv[2] if len(sys.argv) > 2 else "."
        guard = RepoGuard()
        
        import os
        if os.path.isfile(path):
            report = guard.scan_file(path)
        else:
            report = guard.scan_repository(path)
            
        reporter = Reporter()
        reporter.print_report(report)
        
        # Exit with error if findings
        if report['summary']['total_findings'] > 0:
            sys.exit(1)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()