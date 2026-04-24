"""Tests for RepoGuard."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repoguard import RepoGuard
from repoguard.engine.rules_engine import RulesEngine
from repoguard.engine.heuristic_analyzer import HeuristicAnalyzer
from repoguard.models.risk_scorer import RiskScorer


def test_rules_hardcoded_secret():
    engine = RulesEngine()
    code = 'API_KEY = "abcdef1234567890abcdef1234567890"'
    findings = engine.scan(code, "test.py")
    assert len(findings) >= 1, f"Expected finding, got {len(findings)}"
    assert any(f.finding_type == "Secrets Leak" for f in findings), "Expected Secrets Leak"


def test_rules_eval():
    engine = RulesEngine()
    code = 'result = eval(user_input)'
    findings = engine.scan(code, "test.py")
    assert len(findings) >= 1


def test_rules_os_system():
    engine = RulesEngine()
    code = 'os.system(cmd)'
    findings = engine.scan(code, "test.py")
    assert len(findings) >= 1


def test_clean_code():
    engine = RulesEngine()
    code = 'def add(a, b): return a + b'
    findings = engine.scan(code, "test.py")
    assert len(findings) == 0


def test_heuristic_exec():
    analyzer = HeuristicAnalyzer()
    code = 'exec("print(1)")'
    findings = analyzer.analyze(code, "test.py")
    assert len(findings) >= 1


def test_risk_scoring():
    scorer = RiskScorer()
    findings = [
        {"finding_type": "Secrets Leak", "severity": "Critical", "evidence_span": "password=xxx", "line": 1}
    ]
    scores = scorer.score_findings(findings, "code")
    assert len(scores) == 1
    assert scores[0].score > 0.5


def test_escalate():
    scorer = RiskScorer()
    assert scorer.should_escalate(0.9, 0.5, False)
    assert scorer.should_escalate(0.3, 0.5, True)
    assert scorer.should_escalate(0.5, 0.3, False)


def test_scan_code():
    guard = RepoGuard()
    code = '''
import os
API_KEY = "secret123456789012345"
def unsafe():
    eval(input())
'''
    report = guard.scan_code(code, "test.py")
    assert report["summary"]["total_findings"] >= 2


def test_scan_clean():
    guard = RepoGuard()
    code = 'def add(a, b): return a + b'
    report = guard.scan_code(code, "test.py")
    assert report["summary"]["total_findings"] == 0


def test_summary():
    guard = RepoGuard()
    code = 'API_KEY = "secret123456789012345"'
    report = guard.scan_code(code, "test.py")
    summary = report["summary"]
    assert summary["critical_count"] >= 1


if __name__ == "__main__":
    tests = [
        test_rules_hardcoded_secret,
        test_rules_eval,
        test_rules_os_system,
        test_clean_code,
        test_heuristic_exec,
        test_risk_scoring,
        test_escalate,
        test_scan_code,
        test_scan_clean,
        test_summary,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"FAIL: {test.__name__}: {e}")
            failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)