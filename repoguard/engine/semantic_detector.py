"""
Semantic Vulnerability Detector
Uses embeddings to detect vulnerabilities flexibly
"""
import re
import os
import logging
import torch
from typing import List, Dict, Any, Optional

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'

logger = logging.getLogger(__name__)

# Flexible vulnerability descriptions (semantic patterns)
VULNERABILITY_DESCRIPTIONS = {
    "Secrets Leak": [
        "hardcoded password in source code",
        "API key exposed in code",
        "secret token stored in plaintext",
        "credentials embedded in code",
        "private key hardcoded",
        "access token in source",
        "encryption key exposed",
        "service account credentials",
    ],
    "SQL Injection": [
        "SQL query built from string concatenation",
        "database query with user input",
        "unsafe SQL string formatting",
        "raw query from parameter",
    ],
    "XSS": [
        "user input rendered without escaping",
        "HTML from untrusted source",
        "JavaScript injected into page",
        "DOM manipulation with raw HTML",
    ],
    "Command Injection": [
        "shell command from user input",
        "system call with unsanitized parameter",
        "subprocess with shell=True",
        "os command from request",
    ],
    "Path Traversal": [
        "file path from user input",
        "directory traversal vulnerability",
        "unsanitized file path",
        "path concatenation unsafe",
    ],
    "Injection": [
        "eval on user input",
        "execute arbitrary code",
        "dynamic code execution",
        "compile user supplied code",
    ],
    "Insecure Deserialization": [
        "deserialize untrusted data",
        "pickle load user data",
        "yaml unsafe load",
        "unmarshal external data",
    ],
    "Weak Cryptography": [
        "MD5 hash for security",
        "SHA1 hash deprecated",
        "weak encryption algorithm",
        "insecure crypto primitive",
    ],
    "Hardcoded Config": [
        "hardcoded IP address",
        "embedded URL in source",
        "database connection string",
        "hardcoded configuration",
    ],
    "SSRF": [
        "fetch URL from user input",
        "request to arbitrary URL",
        "load content from URL parameter",
    ],
}

# Sensitive data patterns (not just regex - semantic)
SENSITIVE_KEYWORDS = {
    "Critical": ["password", "secret", "key", "token", "api_key", "private", "credential", "auth", "jwt", "access_token", "refresh_token", "encryption_key", "aes", "rsa", "signature"],
    "High": ["admin", "root", "sudo", "passwd", "user", "login", "session", "cookie", "bearer", "oauth"],
    "Medium": ["ip", "address", "url", "endpoint", "host", "port", "database", "db", "connection"],
}


class SemanticFinding:
    """Finding from semantic analysis."""
    def __init__(self, vuln_type: str, severity: str, evidence: str, line: int, confidence: float, method: str = "semantic"):
        self.vuln_type = vuln_type
        self.severity = severity
        self.evidence = evidence
        self.line = line
        self.confidence = confidence
        self.method = method

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": self.vuln_type,
            "severity": self.severity,
            "evidence_span": self.evidence[:100],
            "line": self.line,
            "confidence": self.confidence,
            "method": self.method
        }


class SemanticDetector:
    """
    Uses embeddings to detect vulnerabilities semantically.
    More flexible than regex - learns patterns from code context.
    """
    
    SIMILARITY_THRESHOLD = 0.55  # Lowered for more coverage
    
    def __init__(self, model_name: str = "microsoft/CodeBERT-base"):
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.device = "cpu"
        self.pattern_embeddings = {}
        self._initialize_model()
        self._build_pattern_embeddings()
        
    def _initialize_model(self):
        try:
            from transformers import AutoModel, AutoTokenizer
            
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"Loading {self.model_name}...")
            
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModel.from_pretrained(self.model_name)
            self.model.to(self.device)
            self.model.eval()
            logger.info(f"Semantic detector initialized on {self.device}")
        except Exception as e:
            logger.warning(f"Falling back to MiniLM: {e}")
            self._fallback_to_minilm()
    
    def _fallback_to_minilm(self):
        from transformers import AutoModel, AutoTokenizer
        self.model_name = "sentence-transformers/all-MiniLM-L6-v2"
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModel.from_pretrained(self.model_name)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model.to(self.device)
        self.model.eval()
        
    def _build_pattern_embeddings(self):
        """Pre-compute embeddings for all vulnerability descriptions."""
        if self.model is None:
            return
            
        all_descriptions = []
        self.pattern_mapping = []  # Maps index -> (type, description)
        
        for vuln_type, descriptions in VULNERABILITY_DESCRIPTIONS.items():
            for desc in descriptions:
                all_descriptions.append(desc)
                self.pattern_mapping.append((vuln_type, desc))
        
        if all_descriptions:
            try:
                import torch
                inputs = self.tokenizer(
                    all_descriptions,
                    return_tensors="pt",
                    padding=True,
                    truncation=True,
                    max_length=128
                )
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                
                with torch.no_grad():
                    outputs = self.model(**inputs)
                
                attention_mask = inputs["attention_mask"]
                hidden = outputs.last_hidden_state
                mask = attention_mask.unsqueeze(-1).expand(hidden.size()).float()
                embeddings = (hidden * mask).sum(1) / mask.sum(1)
                
                self.pattern_embeddings = embeddings.cpu()
                logger.info(f"Built {len(all_descriptions)} pattern embeddings")
            except Exception as e:
                logger.warning(f"Could not build embeddings: {e}")
    
    def _get_embedding(self, text: str) -> Optional[torch.Tensor]:
        if self.model is None:
            return None
        try:
            import torch
            inputs = self.tokenizer(
                [text],
                return_tensors="pt",
                truncation=True,
                max_length=256
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
            
            if "attention_mask" in inputs:
                hidden = outputs.last_hidden_state
                mask = inputs["attention_mask"].unsqueeze(-1).expand(hidden.size()).float()
                embedding = (hidden * mask).sum(1) / mask.sum(1)
            else:
                embedding = outputs.last_hidden_state.mean(dim=1)
                
            return embedding.squeeze(0).cpu()
        except Exception as e:
            return None
    
    def _cosine_similarity(self, a: torch.Tensor, b: torch.Tensor) -> float:
        import torch
        a = a / a.norm(dim=-1, keepdim=True)
        b = b / b.norm(dim=-1, keepdim=True)
        return (a * b).sum().item()
    
    def detect(self, code: str, filename: str = "unknown") -> List[SemanticFinding]:
        """
        Detect vulnerabilities using semantic similarity.
        """
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or len(line) < 5:
                continue
            
            # Skip comments
            if line.startswith('#') or line.startswith('//'):
                continue
            
            # Get embedding
            code_embedding = self._get_embedding(line)
            if code_embedding is None:
                continue
            
            best_match = None
            best_similarity = 0
            
            # Compare to all patterns
            for idx, (vuln_type, desc) in enumerate(self.pattern_mapping):
                if idx >= len(self.pattern_embeddings):
                    continue
                sim = self._cosine_similarity(code_embedding, self.pattern_embeddings[idx])
                if sim > best_similarity:
                    best_similarity = sim
                    best_match = (vuln_type, desc)
            
            # If above threshold, create finding
            if best_similarity > self.SIMILARITY_THRESHOLD and best_match:
                vuln_type, _ = best_match
                severity = self._get_severity(vuln_type, line)
                
                findings.append(SemanticFinding(
                    vuln_type=vuln_type,
                    severity=severity,
                    evidence=line[:80],
                    line=i,
                    confidence=best_similarity,
                    method="semantic"
                ))
        
        # Also check for sensitive keywords (complementary signal)
        keyword_findings = self._keyword_scan(code)
        
        # Merge findings
        all_findings = self._merge(findings, keyword_findings)
        
        return all_findings
    
    def _keyword_scan(self, code: str) -> List[SemanticFinding]:
        """Additional keyword-based scan for sensitive data."""
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if '=' not in line:
                continue
                
            text = line.lower()
            for severity, keywords in SENSITIVE_KEYWORDS.items():
                count = sum(1 for kw in keywords if kw in text)
                if count >= 2:  # Multiple sensitive keywords
                    # Check it's an assignment (not just a comment)
                    if ' = ' in line or '=' in line:
                        findings.append(SemanticFinding(
                            vuln_type="Sensitive Data",
                            severity=severity,
                            evidence=line[:80],
                            line=i,
                            confidence=0.6,
                            method="keyword"
                        ))
                        break
        
        return findings
    
    def _get_severity(self, vuln_type: str, evidence: str) -> str:
        evidence_lower = evidence.lower()
        
        critical_types = ["Secrets Leak", "SQL Injection", "Injection", "Insecure Deserialization"]
        high_types = ["Command Injection", "Path Traversal", "SSRF", "XSS"]
        
        if vuln_type in critical_types:
            return "Critical"
        elif vuln_type in high_types:
            return "High"
        elif vuln_type == "Weak Cryptography":
            return "Medium"
        else:
            return "Medium"
    
    def _merge(self, semantic: List[SemanticFinding], keyword: List[SemanticFinding]) -> List[SemanticFinding]:
        """Merge findings from both methods."""
        merged = []
        seen = set()
        
        for f in semantic + keyword:
            key = (f.line, f.vuln_type)
            if key not in seen:
                seen.add(key)
                merged.append(f)
            else:
                # Update confidence if higher
                for existing in merged:
                    if existing.line == f.line and existing.vuln_type == f.vuln_type:
                        if f.confidence > existing.confidence:
                            existing.confidence = f.confidence
                        break
        
        return merged


if __name__ == "__main__":
    detector = SemanticDetector()
    
    test_code = '''
app.secret_key = 'hardcoded_secret_key_12345'
ADMIN_PASSWORD = "SuperSecret123"
API_KEY = "sk-1234567890abcdef"
query = f"SELECT * FROM users WHERE username = '{username}'"
result = eval(user_input)
os.system(cmd)
subprocess.call(cmd, shell=True)
pickle.loads(data)
cursor.execute(query + user_id)
render_template_string('<h1>%s</h1>' % name)
file_path = base_path + filename
hashlib.md5(password.encode()).hexdigest()
'''
    
    findings = detector.detect(test_code, "test.py")
    print(f"Found {len(findings)} vulnerabilities:")
    for f in findings:
        print(f"  [{f.severity}] {f.vuln_type} (conf={f.confidence:.2f}) line {f.line}: {f.method}")