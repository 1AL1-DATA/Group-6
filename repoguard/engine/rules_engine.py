"""
Rule-based Security Scanner
Detects well-known patterns: hardcoded secrets, insecure configurations
"""
import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class RuleFinding:
    """Structure to hold a finding from the rules engine."""
    def __init__(
        self,
        finding_type: str,
        severity: str,
        evidence: str,
        line: int,
        rule_id: str,
        needs_escalation: bool = False
    ):
        self.finding_type = finding_type
        self.severity = severity
        self.evidence = evidence
        self.line = line
        self.rule_id = rule_id
        self.needs_escalation = needs_escalation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "evidence_span": self.evidence,
            "line": self.line,
            "rule_id": self.rule_id,
            "needs_escalation": self.needs_escalation
        }


class RulesEngine:
    """Applies deterministic rules to detect known vulnerability patterns."""
    
    DEFAULT_RULES = [
        {
            "id": "R001",
            "name": "DangerousEval",
            "description": "Insecure use of eval() - allows arbitrary code execution",
            "pattern": r"eval\s*\(",
            "severity": "High",
            "finding_type": "Injection",
            "needs_escalation": False
        },
        {
            "id": "R002",
            "name": "UnsafeSystemCall",
            "description": "Use of os.system() - command injection risk",
            "pattern": r"os\.system\s*\(",
            "severity": "Medium",
            "finding_type": "Misconfiguration",
            "needs_escalation": False
        },
        {
            "id": "R003",
            "name": "HardcodedAPISecret",
            "description": "Hardcoded API key or secret detected",
            "pattern": r"(API_KEY|API_SECRET|SECRET_KEY|PRIVATE_KEY)\s*=\s*[\"'][a-zA-Z0-9]{16,}[\"']",
            "severity": "Critical",
            "finding_type": "Secrets Leak",
            "needs_escalation": True
        },
        {
            "id": "R004",
            "name": "HardcodedPassword",
            "description": "Hardcoded password detected",
            "pattern": r"password\s*=\s*[\"'][^\"']+[\"']",
            "severity": "Critical",
            "finding_type": "Secrets Leak",
            "needs_escalation": True
        },
        {
            "id": "R005",
            "name": "SQLInjection",
            "description": "Potential SQL injection - string concatenation in query",  
            "pattern": r"(cursor\.execute|fetchall|fetchone)\s*\([^,)]*\+",
            "severity": "Critical",
            "finding_type": "SQL Injection",
            "needs_escalation": True
        },
        {
            "id": "R006",
            "name": "UnsafePickle",
            "description": "Use of pickle Unpickler - arbitrary code execution risk",
            "pattern": r"pickle\.loads?\s*\(",
            "severity": "High",
            "finding_type": "Insecure Deserialization",
            "needs_escalation": True
        },
        {
            "id": "R011",
            "name": "PathTraversal",
            "description": "Path concatenation without sanitization",
            "pattern": r"\w+\s*=\s*\w+\s*\+\s*\w+.*(?:path|file|dir)",
            "severity": "High",
            "finding_type": "Path Traversal",
            "needs_escalation": False
        },
        {
            "id": "R012",
            "name": "XSSRenderTemplate",
            "description": "XSS via render_template_string with string formatting",
            "pattern": r"render_template_string\s*\([^)]*%s",
            "severity": "Critical",
            "finding_type": "XSS",
            "needs_escalation": True
        },
        {
            "id": "R007",
            "name": "WeakCryptography",
            "description": "Use of weak crypto (MD5, SHA1) for security",
            "pattern": r"(md5|sha1)\s*\(",
            "severity": "Medium",
            "finding_type": "Weak Cryptography",
            "needs_escalation": False
        },
        {
            "id": "R008",
            "name": "HardcodedSalt",
            "description": "Hardcoded salt detected",
            "pattern": r"SALT\s*=\s*[\"'][a-zA-Z0-9+/=]{8,}[\"']",
            "severity": "Medium",
            "finding_type": "Secrets Leak",
            "needs_escalation": False
        },
        {
            "id": "R009",
            "name": "UnverifiedSSL",
            "description": "SSL verification disabled",
            "pattern": r"\.(verify|check_hostname)\s*=\s*False",
            "severity": "High",
            "finding_type": "Insecure Connection",
            "needs_escalation": True
        },
        {
            "id": "R010",
            "name": "DebugMode",
            "description": "Debug mode enabled in production",
            "pattern": r"DEBUG\s*=\s*True",
            "severity": "Medium",
            "finding_type": "Misconfiguration",
            "needs_escalation": False
        }
    ]
    
    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize rules engine.
        
        Args:
            rules_path: Optional path to JSON rules file
        """
        self.rules_path = rules_path
        self.rules = []
        self._load_rules()
        
    def _load_rules(self) -> None:
        """Load rules from file or use defaults."""
        if self.rules_path and Path(self.rules_path).exists():
            try:
                with open(self.rules_path, 'r') as f:
                    self.rules = json.load(f)
                logger.info(f"Loaded {len(self.rules)} rules from {self.rules_path}")
            except Exception as e:
                logger.warning(f"Could not load rules: {e}, using defaults")
                self.rules = self.DEFAULT_RULES
        else:
            self.rules = self.DEFAULT_RULES
            logger.info(f"Using {len(self.rules)} default rules")
    
    def scan(self, code_content: str, filename: str = "unknown") -> List[RuleFinding]:
        """
        Scan code content against all rules.
        
        Args:
            code_content: Source code to scan
            filename: File being scanned
            
        Returns:
            List of RuleFinding objects
        """
        findings = []
        
        for rule in self.rules:
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
                
            try:
                matches = list(re.finditer(pattern, code_content, re.MULTILINE))
                
                for match in matches:
                    start_char = match.start()
                    line_num = code_content[:start_char].count("\n") + 1
                    
                    finding = RuleFinding(
                        finding_type=rule["finding_type"],
                        severity=rule["severity"],
                        evidence=match.group(0),
                        line=line_num,
                        rule_id=rule["id"],
                        needs_escalation=rule.get("needs_escalation", False)
                    )
                    findings.append(finding)
                    
            except re.error as e:
                logger.warning(f"Invalid regex in rule {rule.get('id')}: {e}")
                
        logger.debug(f"Rules engine found {len(findings)} findings in {filename}")
        return findings
    
    def scan_file(self, file_path: str) -> List[RuleFinding]:
        """Scan a single file."""
        path = Path(file_path)
        if not path.exists():
            return []
            
        content = path.read_text(encoding='utf-8', errors='ignore')
        return self.scan(content, str(path.name))
    
    def add_rule(self, rule: Dict[str, Any]) -> None:
        """Add a new rule."""
        if "id" in rule and "pattern" in rule:
            self.rules.append(rule)
            logger.info(f"Added rule: {rule['id']}")
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r.get("id") != rule_id]
        return len(self.rules) < initial_len


if __name__ == "__main__":
    # Test
    engine = RulesEngine()
    test_code = '''
import os
API_KEY = "abcdef1234567890abcdef1234567890"
def unsafe(data):
    result = eval(data)
    os.system(data)
'''
    findings = engine.scan(test_code, "test.py")
    for f in findings:
        print(f"[{f.severity}] {f.finding_type} at line {f.line}: {f.evidence}")