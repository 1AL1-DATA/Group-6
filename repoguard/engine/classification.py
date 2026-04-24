"""
Severity Classification System
===========================
Defines severity levels with detailed descriptions for vulnerability findings.

Risk Levels:
- CRITICAL: Direct RCE or complete data breach
- HIGH: Significant impact, requires urgent fix
- MEDIUM: Moderate risk, should be addressed
- LOW: Minor issue, can defer
- INFO: Informational, best practices
- POTENTIAL: Needs manual review to confirm
"""

from enum import IntEnum
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


class Severity(IntEnum):
    """Severity levels with numeric priorities."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    POTENTIAL = 0


# Vulnerability descriptions and classifications
VULNERABILITY_DICT = {
    # Critical - Direct Code Execution / Full Data Breach
    "Injection": {
        "severity": Severity.CRITICAL,
        "risk": "Arbitrary code execution possible",
        "description": "User input directly executed as code. Allows complete system compromise.",
        "examples": ["eval(user_input)", "exec(code)", "__import__('os').system('ls')"],
        "fix": "Use safe parsing libraries, never eval user input"
    },
    "Insecure Deserialization": {
        "severity": Severity.CRITICAL,
        "risk": "Object injection leads to RCE",
        "description": "Deserializing untrusted data can execute arbitrary code.",
        "examples": ["pickle.loads(data)", "yaml.load(unsafedata)", "eval(marshal.loads(x))"],
        "fix": "Use JSON, validate with schema, yaml.safe_load"
    },
    "Secrets Leak": {
        "severity": Severity.CRITICAL,
        "risk": "Credentials exposed to attackers",
        "description": "Hardcoded secrets in source visible to anyone with code access.",
        "examples": ["API_KEY='xxx'", "password='secret'", "private_key='key'"],
        "fix": "Use environment variables, secret managers"
    },
    
    # High - Significant Data/Access Impact
    "SQL Injection": {
        "severity": Severity.HIGH,
        "risk": "Database compromise, data exfiltration",
        "description": "SQL queries built from user input allow database manipulation.",
        "examples": ["query=f'SELECT * WHERE id=' + user_id", "cursor.execute(query + id)"],
        "fix": "Parameterized queries, ORM Eloquent"
    },
    "Command Injection": {
        "severity": Severity.HIGH,
        "risk": "Shell access to server",
        "description": "User input passed to shell commands.",
        "examples": ["os.system(cmd)", "subprocess.call(shell=True)"],
        "fix": "Use list form, sanitize input"
    },
    "Path Traversal": {
        "severity": Severity.HIGH,
        "risk": "Read/write arbitrary files",
        "description": "File paths constructed from user input allow file access.",
        "examples": ["open(path + file)", "readfile(user_file)"],
        "fix": "Validate path, use whitelist"
    },
    "XXE": {
        "severity": Severity.HIGH,
        "risk": "Read server files, SSRF",
        "description": "XML parser allows external entity access.",
        "examples": ["ET.fromstring(xml)", "xmlParser()"],
        "fix": "Disable external entities"
    },
    "SSRF": {
        "severity": Severity.HIGH,
        "risk": "Access internal services",
        "description": "User-controlled URL fetch allows internal network access.",
        "examples": ["requests.get(url)", "urllib.open(url)"],
        "fix": "Validate URLs, block internal IPs"
    },
    
    # Medium - Partial Impact
    "XSS": {
        "severity": Severity.MEDIUM,
        "risk": "Session hijacking, defacement",
        "description": "User input rendered without escaping.",
        "examples": ["innerHTML=x", "render_template_string('%s' % name)"],
        "fix": "Escape output, use template engines"
    },
    "Weak Cryptography": {
        "severity": Severity.MEDIUM,
        "risk": "Cracked with moderate effort",
        "description": "Weak crypto algorithms can be broken.",
        "examples": ["md5()", "sha1()", "DES"],
        "fix": "Use bcrypt, argon2, AES-256"
    },
    "IDOR": {
        "severity": Severity.MEDIUM,
        "risk": "Access other users' data",
        "description": "No ownership check on resource access.",
        "examples": ["user_id = request.param", "SELECT WHERE id=" + uid],
        "fix": "Verify ownership, use session"
    },
    "Open Redirect": {
        "severity": Severity.MEDIUM,
        "risk": "Phishing, trust exploitation",
        "description": "Redirects user to attacker-controlled URL.",
        "examples": ["redirect(url)", "Location: " + target],
        "fix": "Validate redirect URLs"
    },
    "Weak Authentication": {
        "severity": Severity.MEDIUM,
        "risk": "Account takeover",
        "description": "Predictable tokens or weak auth flow.",
        "examples": ["mt_rand()", "jwt(none)", "timestamp"],
        "fix": "Secure tokens, JWT with verification"
    },
    
    # Low - Minor Issues
    "Misconfiguration": {
        "severity": Severity.LOW,
        "risk": "Information disclosure",
        "description": "Configuration exposes information.",
        "examples": ["debug=True", "display_errors=On"],
        "fix": "Disable in production"
    },
    "Information Disclosure": {
        "severity": Severity.LOW,
        "risk": "Reveals system details",
        "description": "Error messages or debug info exposed.",
        "examples": ["traceback.format_exc()", "phpinfo()"],
        "fix": "Generic error messages"
    },
    "Hardcoded Config": {
        "severity": Severity.LOW,
        "risk": "Hard to rotate, not scalable",
        "description": "Configuration in code, not environment.",
        "examples": ["host='localhost'", "timeout=30"],
        "fix": "Use config files, env vars"
    },
    
    # Informational - Best Practices
    "Rate Limiting": {
        "severity": Severity.INFO,
        "risk": "Brute force possible",
        "description": "No rate limiting on sensitive endpoints.",
        "examples": ["no login rate limit"],
        "fix": "Implement rate limiting"
    },
    "Logging": {
        "severity": Severity.INFO,
        "risk": "Audit trail incomplete",
        "description": "Important actions not logged.",
        "examples": ["no audit logging"],
        "fix": "Add audit logging"
    },
    "CSRF": {
        "severity": Severity.INFO,
        "risk": "State-changing requests vulnerable",
        "description": "No CSRF protection on forms.",
        "examples": ["no csrf token"],
        "fix": "Add CSRF tokens"
    },
    
    # Potential - Needs Manual Review
    "Potential Injection": {
        "severity": Severity.POTENTIAL,
        "risk": "Could be vulnerable depending on context",
        "description": "Pattern matches but needs code review to confirm.",
        "examples": ["constructors that could be unsafe"],
        "fix": "Manual review required"
    },
    "Potential SSTI": {
        "severity": Severity.POTENTIAL,
        "risk": "Template injection possibility",
        "description": "String formatting in templates could allow injection.",
        "examples": ["format string in template"],
        "fix": "Use Jinja2 autoescape"
    },
    "Potential Cryptography": {
        "severity": Severity.POTENTIAL,
        "risk": "Crypto use requires review",
        "description": "Encryption present, needs key review.",
        "examples": ["fernet encrypt", "hmac"],
        "fix": "Verify key management"
    },
}


@dataclass
class Classification:
    """Complete vulnerability classification."""
    vuln_type: str
    severity: Severity
    confidence: float
    description: str
    risk: str
    examples: List[str]
    fix: str
    
    @classmethod
    def from_type(cls, vuln_type: str, confidence: float = 0.8) -> 'Classification':
        """Create from vulnerability type."""
        data = VULNERABILITY_DICT.get(vuln_type, {
            "severity": Severity.POTENTIAL,
            "risk": "Unknown",
            "description": "Unknown vulnerability type",
            "examples": [],
            "fix": "Manual review required"
        })
        return cls(
            vuln_type=vuln_type,
            severity=data["severity"],
            confidence=confidence,
            description=data["description"],
            risk=data["risk"],
            examples=data["examples"],
            fix=data["fix"]
        )


def classify_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add classification data to findings."""
    classified = []
    for finding in findings:
        vuln_type = finding.get("finding_type", "Unknown")
        confidence = finding.get("confidence", 0.8)
        
        classification = Classification.from_type(vuln_type, confidence)
        
        finding["severity"] = classification.severity.name
        finding["classification"] = {
            "risk": classification.risk,
            "description": classification.description,
            "examples": classification.examples[:3],
            "fix": classification.fix
        }
        classified.append(finding)
    
    return classified


if __name__ == "__main__":
    # Test
    for vuln_type in ["SQL Injection", "XSS", "Weak Cryptography", "Potential Injection"]:
        c = Classification.from_type(vuln_type)
        print(f"\n[{c.severity.name}] {vuln_type}")
        print(f"  Risk: {c.risk}")
        print(f"  Description: {c.description}")
        print(f"  Fix: {c.fix}")