"""
Heuristic Code Analyzer
Uses semantic similarity with MiniLM for better pattern detection
"""
import re
import logging
import os
import torch
from typing import List, Dict, Any, Tuple, Optional

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'

logger = logging.getLogger(__name__)

# Known vulnerability patterns with embeddings (expanded to 60+ patterns)
VULNERABILITY_PATTERNS = [
    # Secrets / Hardcoded Credentials (10)
    {"name": "hardcoded_key", "type": "Secrets Leak", "text": "hardcoded API key in source code", "severity": "Critical"},
    {"name": "hardcoded_password", "type": "Secrets Leak", "text": "hardcoded password stored in code", "severity": "Critical"},
    {"name": "hardcoded_secret", "type": "Secrets Leak", "text": "secret token hardcoded in source", "severity": "Critical"},
    {"name": "hardcoded_username", "type": "Secrets Leak", "text": "username embedded in code", "severity": "Critical"},
    {"name": "hardcoded_credential", "type": "Secrets Leak", "text": "credentials in source code", "severity": "Critical"},
    {"name": "hardcoded_token", "type": "Secrets Leak", "text": "access token exposed", "severity": "Critical"},
    {"name": "hardcoded_secret_key", "type": "Secrets Leak", "text": "flask secret key hardcoded", "severity": "Critical"},
    {"name": "env_without_default", "type": "Secrets Leak", "text": "environment variable accessed", "severity": "High"},
    {"name": "secrets_manager", "type": "Secrets Leak", "text": "secrets manager client", "severity": "Medium"},
    {"name": "config_secret", "type": "Secrets Leak", "text": "configuration contains secret", "severity": "High"},
    
    # Injection (8)
    {"name": "eval_injection", "type": "Injection", "text": "eval executes arbitrary Python code", "severity": "High"},
    {"name": "exec_code", "type": "Injection", "text": "exec runs dynamic code strings", "severity": "High"},
    {"name": "compile_dynamic", "type": "Injection", "text": "compile creates dynamic code", "severity": "High"},
    {"name": "input_eval", "type": "Injection", "text": "input passed to eval", "severity": "High"},
    {"name": "map_eval", "type": "Injection", "text": "map with eval function", "severity": "High"},
    {"name": "apply_eval", "type": "Injection", "text": "apply with eval", "severity": "High"},
    {"name": "callable_exec", "type": "Injection", "text": "callable execution", "severity": "High"},
    {"name": " getattr_abuse", "type": "Injection", "text": "getattr with user input", "severity": "High"},
    
    # SQL Injection (5)
    {"name": "sql_concat", "type": "SQL Injection", "text": "SQL query string concatenation", "severity": "Critical"},
    {"name": "sql_fstring", "type": "SQL Injection", "text": "f-string builds SQL query", "severity": "Critical"},
    {"name": "sql_format", "type": "SQL Injection", "text": "format string in SQL query", "severity": "Critical"},
    {"name": "sql_execute_raw", "type": "SQL Injection", "text": "raw cursor execute", "severity": "Critical"},
    {"name": "sql_user_id", "type": "SQL Injection", "text": "user id in SQL query", "severity": "Critical"},
    
    # Command Injection (5)
    {"name": "system_call", "type": "Command Injection", "text": "os.system executes shell commands", "severity": "High"},
    {"name": "subprocess_shell", "type": "Command Injection", "text": "subprocess with shell=True dangerous", "severity": "High"},
    {"name": "popen_shell", "type": "Command Injection", "text": "popen runs shell commands", "severity": "High"},
    {"name": "commands_exec", "type": "Command Injection", "text": "commands module shell", "severity": "High"},
    {"name": "shell_bash", "type": "Command Injection", "text": "bash -c command execution", "severity": "High"},
    
    # Deserialization (5)
    {"name": "pickle_load", "type": "Insecure Deserialization", "text": "pickle loads untrusted data", "severity": "High"},
    {"name": "yaml_unsafe", "type": "Insecure Deserialization", "text": "yaml load without safe loader", "severity": "High"},
    {"name": "marshal_load", "type": "Insecure Deserialization", "text": "marshal loads bytecode", "severity": "High"},
    {"name": "eval_pickle", "type": "Insecure Deserialization", "text": "eval deserializes data", "severity": "High"},
    {"name": "unserialize_user", "type": "Insecure Deserialization", "text": "deserialize user data", "severity": "High"},
    
    # XSS (5)
    {"name": "render_string_xss", "type": "XSS", "text": "render_template_string with string formatting", "severity": "Critical"},
    {"name": "innerHTML_xss", "type": "XSS", "text": "innerHTML sets unsanitized HTML", "severity": "Critical"},
    {"name": "document_write", "type": "XSS", "text": "document.write raw HTML", "severity": "Critical"},
    {"name": "html_unescape", "type": "XSS", "text": "HTML unescaped in output", "severity": "High"},
    {"name": "safe_markdown", "type": "XSS", "text": "markdown to HTML unsafe", "severity": "High"},
    
    # Path Traversal (5)
    {"name": "path_concat", "type": "Path Traversal", "text": "file path from user input concatenated", "severity": "High"},
    {"name": "path_join", "type": "Path Traversal", "text": "path join without validation", "severity": "High"},
    {"name": "file_open", "type": "Path Traversal", "text": "open file from parameter", "severity": "High"},
    {"name": "send_file", "type": "Path Traversal", "text": "send file arbitrary path", "severity": "High"},
    {"name": "path_traversal", "type": "Path Traversal", "text": "directory traversal attack", "severity": "High"},
    
    # Weak Crypto (5)
    {"name": "md5_hash", "type": "Weak Cryptography", "text": "MD5 hash for security weak", "severity": "Medium"},
    {"name": "sha1_hash", "type": "Weak Cryptography", "text": "SHA1 hash insecure", "severity": "Medium"},
    {"name": "des_cipher", "type": "Weak Cryptography", "text": "DES encryption broken", "severity": "Medium"},
    {"name": "rc4_cipher", "type": "Weak Cryptography", "text": "RC4 cipher weak", "severity": "Medium"},
    {"name": "base64_crypto", "type": "Weak Cryptography", "text": "base64 encoding not encryption", "severity": "Medium"},
    
    # Info Disclosure (5)
    {"name": "traceback_expose", "type": "Information Disclosure", "text": " traceback exposed to client", "severity": "High"},
    {"name": "error_expose", "type": "Information Disclosure", "text": "full error details shown", "severity": "High"},
    {"name": "stack_expose", "type": "Information Disclosure", "text": "stack trace exposed", "severity": "High"},
    {"name": "debug_error", "type": "Information Disclosure", "text": "debug error handler", "severity": "High"},
    {"name": "log_sensitive", "type": "Information Disclosure", "text": "logging sensitive data", "severity": "Medium"},
    
    # SSRF (3)
    {"name": "url_open", "type": "SSRF", "text": "urlopen fetches external URL", "severity": "High"},
    {"name": "requests_url", "type": "SSRF", "text": "requests with unvalidated URL", "severity": "High"},
    {"name": "urllib_url", "type": "SSRF", "text": "urllib open arbitrary URL", "severity": "High"},
    
    # IDOR (2)
    {"name": "idor_profile", "type": "IDOR", "text": "user profile direct object reference", "severity": "High"},
    {"name": "idor_file", "type": "IDOR", "text": "file access without check", "severity": "High"},
    
    # Misconfiguration (4)
    {"name": "debug_mode", "type": "Misconfiguration", "text": "debug mode enabled", "severity": "Medium"},
    {"name": "cors_allow", "type": "Misconfiguration", "text": "CORS allows all origins", "severity": "Medium"},
    {"name": "ssl_verify", "type": "Misconfiguration", "text": "SSL verification disabled", "severity": "High"},
    {"name": "host_any", "type": "Misconfiguration", "text": "bind to all interfaces", "severity": "Low"},
]

# Regex patterns for fast initial filtering (expanded to 50+)
REGEX_PATTERNS = [
    # Code Execution / Injection (CRITICAL)
    {"name": "exec_usage", "pattern": r"exec\s*\(", "type": "Injection", "severity": "Critical"},
    {"name": "eval_usage", "pattern": r"eval\s*\(", "type": "Injection", "severity": "Critical"},
    {"name": "compile_usage", "pattern": r"compile\s*\(", "type": "Injection", "severity": "Critical"},
    {"name": "__import__", "pattern": r"__import__\s*\(", "type": "Injection", "severity": "Critical"},
    {"name": "getattr_dynamic", "pattern": r"getattr\([^,)]+\s*,\s*\w+\)", "type": "Injection", "severity": "Critical"},
    
    # Command Injection (HIGH)
    {"name": "system_call", "pattern": r"os\.system\s*\(", "type": "Command Injection", "severity": "High"},
    {"name": "subprocess_shell", "pattern": r"subprocess\.(call|Popen|run)\s*\([^,)]*shell\s*=\s*True", "type": "Command Injection", "severity": "High"},
    {"name": "popen", "pattern": r"os\.popen\s*\(", "type": "Command Injection", "severity": "High"},
    {"name": "commands_call", "pattern": r"commands\.(getoutput|getstatus)", "type": "Command Injection", "severity": "High"},
    {"name": "shell_true", "pattern": r"shell\s*=\s*True", "type": "Command Injection", "severity": "High"},
    
    # SQL Injection (HIGH)
    {"name": "sql_concat", "pattern": r"(execute|fetchall|cursor\.execute)\s*\([^,)]*\+", "type": "SQL Injection", "severity": "High"},
    {"name": "sql_fstring", "pattern": r"(execute|fetchall)\s*\(f[\"'](select|insert|update|delete)", "type": "SQL Injection", "severity": "High"},
    {"name": "sql_order_by", "pattern": r"ORDER BY\s*\$|\+", "type": "SQL Injection", "severity": "High"},
    
    # Secrets / Credentials (CRITICAL)
    {"name": "hardcoded_secret", "pattern": r"(password|secret|token|key|credential)\s*=\s*['\"][^'\"]{8,}['\"]", "type": "Secrets Leak", "severity": "Critical"},
    {"name": "flask_secret", "pattern": r"app\.secret_key\s*=\s*['\"]", "type": "Secrets Leak", "severity": "Critical"},
    {"name": "api_key", "pattern": r"(API_KEY|APIKEY|api_key)\s*=\s*['\"]", "type": "Secrets Leak", "severity": "Critical"},
    {"name": "private_key", "pattern": r"(PRIVATE_KEY|private_key)\s*=\s*['\"]", "type": "Secrets Leak", "severity": "Critical"},
    {"name": "jwt_secret", "pattern": r"(JWT_SECRET|jwt_secret)\s*=\s*['\"]", "type": "Secrets Leak", "severity": "Critical"},
    {"name": "db_password", "pattern": r"db_user\s*=\s*['\"][^'\"]+['\"]", "type": "Secrets Leak", "severity": "Critical"},
    
    # Authentication / JWT (MEDIUM)
    {"name": "jwt_none", "pattern": r"algorithm\s*=\s*['\"]none['\"]", "type": "Weak Authentication", "severity": "Medium"},
    {"name": "jwt_verify_false", "pattern": r"verify_signature\s*=\s*False", "type": "Weak Authentication", "severity": "Medium"},
    {"name": "mt_rand_token", "pattern": r"mt_rand\s*\(\s*\)", "type": "Weak Authentication", "severity": "Medium"},
    {"name": "timestamp_token", "pattern": r"int\s*\(\s*time\.\s*time\s*\(\s*\)\s*\)", "type": "Weak Authentication", "severity": "Medium"},
    
    # Deserialization (CRITICAL)
    {"name": "pickle_load", "pattern": r"pickle\.loads?\s*\(", "type": "Insecure Deserialization", "severity": "Critical"},
    {"name": "yaml_load", "pattern": r"yaml\.load\s*\([^,)]*\)", "type": "Insecure Deserialization", "severity": "Critical"},
    {"name": "marshal_load", "pattern": r"marshal\.load\s*\(", "type": "Insecure Deserialization", "severity": "Critical"},
    {"name": "unserialize", "pattern": r"unserialize\s*\(", "type": "Insecure Deserialization", "severity": "Critical"},
    
    # XSS (MEDIUM)
    {"name": "render_template_string", "pattern": r"render_template_string\s*\([^)]*%", "type": "XSS", "severity": "Medium"},
    {"name": "innerHTML", "pattern": r"innerHTML\s*=", "type": "XSS", "severity": "Medium"},
    {"name": "document_write", "pattern": r"document\.write\s*\(", "type": "XSS", "severity": "Medium"},
    {"name": "dangerouslySetInnerHTML", "pattern": r"dangerouslySetInnerHTML", "type": "XSS", "severity": "Medium"},
    
    # Path Traversal (HIGH)
    {"name": "path_concat", "pattern": r"\w+\s*=\s*(\w+\s*\+|\bjoin\b).*(?:path|file|dir|name)", "type": "Path Traversal", "severity": "High"},
    {"name": "send_file", "pattern": r"send_file\(|send_from_directory\(", "type": "Path Traversal", "severity": "High"},
    {"name": "open_file", "pattern": r"open\([^,)]*\+", "type": "Path Traversal", "severity": "High"},
    {"name": "readfile", "pattern": r"readfile\(", "type": "Path Traversal", "severity": "High"},
    
    # Weak Crypto (MEDIUM)
    {"name": "md5_hash", "pattern": r"hashlib\.md5\s*\(", "type": "Weak Cryptography", "severity": "Medium"},
    {"name": "sha1_hash", "pattern": r"hashlib\.sha1\s*\(", "type": "Weak Cryptography", "severity": "Medium"},
    {"name": "random_usage", "pattern": r"random\.(random|randint|choice)\s*\(", "type": "Weak Cryptography", "severity": "Medium"},
    {"name": "des_cipher", "pattern": r"DES\(", "type": "Weak Cryptography", "severity": "Medium"},
    {"name": "rc4_cipher", "pattern": r"RC4\(", "type": "Weak Cryptography", "severity": "Medium"},
    
    # SSL/TLS Issues (MEDIUM)
    {"name": "ssl_verify_false", "pattern": r"(verify|check_hostname)\s*=\s*False", "type": "Insecure Connection", "severity": "Medium"},
    {"name": "create_unverified", "pattern": r"_create_unverified_context", "type": "Insecure Connection", "severity": "Medium"},
    {"name": "ssl_context_none", "pattern": r"context\s*=\s*None", "type": "Insecure Connection", "severity": "Medium"},
    
    # Configuration Issues (LOW)
    {"name": "debug_true", "pattern": r"debug\s*=\s*True", "type": "Misconfiguration", "severity": "Low"},
    {"name": "cors_allow_all", "pattern": r"['\"]Access-Control-Allow-Origin['\"]\s*=\s*['\"]\*['\"]", "type": "Misconfiguration", "severity": "Low"},
    {"name": "display_errors", "pattern": r"display_errors\s*=\s*True", "type": "Information Disclosure", "severity": "Low"},
    {"name": "phpinfo", "pattern": r"phpinfo\s*\(\s*\)", "type": "Information Disclosure", "severity": "Low"},
    {"name": "traceback", "pattern": r"traceback\.format_exc\(", "type": "Information Disclosure", "severity": "Low"},
    
    # IDOR / Access Control (MEDIUM)
    {"name": "user_id_param", "pattern": r"(request\.args\.get\(|request\.json\.get\()['\"]user_id", "type": "IDOR", "severity": "Medium"},
    {"name": "direct_object", "pattern": r"(get_by_id|find_by_id)\s*\(\s*\w+\)", "type": "IDOR", "severity": "Medium"},
    {"name": "no_owner_check", "pattern": r"WHERE id\s*=\s*\w+\s*(?!session)", "type": "IDOR", "severity": "Medium"},
    
    # SSRF (HIGH)
    {"name": "urlopen", "pattern": r"urllib\.request\.urlopen\(", "type": "SSRF", "severity": "High"},
    {"name": "requests_get", "pattern": r"requests\.(get|post)\s*\([^)]*\)", "type": "SSRF", "severity": "High"},
    {"name": "file_get_contents", "pattern": r"file_get_contents\s*\(\s*\$\_", "type": "SSRF", "severity": "High"},
    
    # Open Redirect (MEDIUM)
    {"name": "redirect", "pattern": r"redirect\s*\(\s*\$|header\(['\"]Location:", "type": "Open Redirect", "severity": "Medium"},
    {"name": "header_location", "pattern": r"header\(['\"]Location:\s*['\"]\s*\.\s*\$", "type": "Open Redirect", "severity": "Medium"},
    
    # CRLF Injection (MEDIUM)
    {"name": "crlf_cookie", "pattern": r"set_cookie\([^,)]*\+|header\([^)\)]*\+", "type": "CRLF Injection", "severity": "Medium"},
    {"name": "header_injection", "pattern": r"header\(['\"]\w+:\s*['\"]\s*\+", "type": "CRLF Injection", "severity": "Medium"},
    
    # Log Injection (LOW)
    {"name": "log_write", "pattern": r"(file_put_contents|logging|write)\s*\([^)]*\$_(GET|POST|REQUEST)", "type": "Log Injection", "severity": "Low"},
    {"name": "fwrite", "pattern": r"fwrite\s*\([^)]*\$", "type": "Log Injection", "severity": "Low"},
    
    # SSTI (MEDIUM)
    {"name": "ssti", "pattern": r"(render_template_string|f【StringTemplate)\s*\([^)]*\$", "type": "Potential SSTI", "severity": "Potential"},
    {"name": "template_injection", "pattern": r"Template\s*\(\s*\$", "type": "Potential SSTI", "severity": "Potential"},
    
    # File Upload (MEDIUM)
    {"name": "file_upload", "pattern": r"(move_uploaded_file|file\.save)\s*\(", "type": "Unrestricted File Upload", "severity": "Medium"},
    {"name": "no_extension_check", "pattern": r"\.save\([^)]*\$", "type": "Unrestricted File Upload", "severity": "Medium"},
]


class HeuristicFinding:
    """Finding from heuristic analysis."""
    def __init__(
        self,
        finding_type: str,
        severity: str,
        evidence: str,
        line: int,
        pattern: str,
        confidence: float = 0.5
    ):
        self.finding_type = finding_type
        self.severity = severity
        self.evidence = evidence
        self.line = line
        self.pattern = pattern
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "evidence_span": self.evidence,
            "line": self.line,
            "pattern": self.pattern,
            "confidence": self.confidence
        }


class HeuristicAnalyzer:
    """
    Analyzes code structure using semantic similarity.
    Uses MiniLM embeddings to detect vulnerability patterns.
    """
    
    SIMILARITY_THRESHOLD = 0.65  # Threshold for semantic match
    
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        """
        Initialize heuristic analyzer.
        
        Args:
            model_name: Model for embeddings
        """
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.device = "cpu"
        self.pattern_embeddings = None
        self._initialize_model()
        self._precompute_patterns()
        
    def _initialize_model(self) -> None:
        """Initialize the embedding model."""
        try:
            from transformers import AutoModel, AutoTokenizer
            
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            logger.info(f"Loading {self.model_name} on {self.device}...")
            
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModel.from_pretrained(self.model_name)
            self.model.to(self.device)
            self.model.eval()
            logger.info("Heuristic analyzer initialized with MiniLM")
            
        except Exception as e:
            logger.warning(f"Could not load model: {e}, using regex-only mode")
            self.model = None
    
    def _precompute_patterns(self) -> None:
        """Pre-compute embeddings for known vulnerability patterns."""
        if self.model is None:
            return
            
        try:
            import torch
            
            texts = [p["text"] for p in VULNERABILITY_PATTERNS]
            
            inputs = self.tokenizer(
                texts,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=128
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                
            # Mean pooling
            attention_mask = inputs["attention_mask"]
            hidden = outputs.last_hidden_state
            mask = attention_mask.unsqueeze(-1).expand(hidden.size()).float()
            masked = hidden * mask
            embeddings = masked.sum(1) / mask.sum(1)
            
            self.pattern_embeddings = embeddings.cpu()
            logger.info(f"Pre-computed {len(texts)} pattern embeddings")
            
        except Exception as e:
            logger.warning(f"Could not precompute patterns: {e}")
    
    def _get_embedding(self, text: str) -> Optional[torch.Tensor]:
        """Get embedding for a text snippet."""
        if self.model is None:
            return None
            
        try:
            import torch
            
            inputs = self.tokenizer(
                [text],
                return_tensors="pt",
                truncation=True,
                max_length=128
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                
            attention_mask = inputs["attention_mask"]
            hidden = outputs.last_hidden_state
            mask = attention_mask.unsqueeze(-1).expand(hidden.size()).float()
            masked = hidden * mask
            embedding = masked.sum(1) / mask.sum(1)
            
            return embedding.squeeze(0).cpu()
            
        except Exception as e:
            logger.warning(f"Embedding error: {e}")
            return None
    
    def _cosine_similarity(self, a: torch.Tensor, b: torch.Tensor) -> float:
        """Compute cosine similarity between embeddings."""
        import torch
        
        a = a / a.norm(dim=-1, keepdim=True)
        b = b / b.norm(dim=-1, keepdim=True)
        return (a * b).sum().item()
    
    def analyze(self, code_content: str, filename: str = "unknown") -> List[HeuristicFinding]:
        """
        Run heuristic analysis on code.
        
        Args:
            code_content: Source code to analyze
            filename: File being analyzed
            
        Returns:
            List of HeuristicFinding objects
        """
        findings = []
        
        # Stage 1: Fast regex filtering
        regex_findings = self._regex_scan(code_content)
        findings.extend(regex_findings)
        
        # Stage 2: Semantic similarity (if model available)
        if self.model is not None and self.pattern_embeddings is not None:
            semantic_findings = self._semantic_scan(code_content)
            findings.extend(semantic_findings)
        
        # Deduplicate by line and type
        findings = self._deduplicate(findings)
        
        logger.debug(f"Heuristic analyzer found {len(findings)} findings in {filename}")
        return findings
    
    def _regex_scan(self, code_content: str) -> List[HeuristicFinding]:
        """Fast regex-based scanning."""
        findings = []
        
        for pattern_def in REGEX_PATTERNS:
            pattern = pattern_def.get("pattern", "")
            if not pattern:
                continue
                
            try:
                matches = list(re.finditer(pattern, code_content, re.MULTILINE | re.IGNORECASE))
                
                for match in matches:
                    start_char = match.start()
                    line_num = code_content[:start_char].count("\n") + 1
                    
                    lines = code_content.split('\n')
                    context = ""
                    if 0 <= line_num - 1 < len(lines):
                        context = lines[line_num - 1].strip()[:100]
                    
                    finding = HeuristicFinding(
                        finding_type=pattern_def["type"],
                        severity=pattern_def["severity"],
                        evidence=context,
                        line=line_num,
                        pattern=pattern_def["name"],
                        confidence=0.7
                    )
                    findings.append(finding)
                    
            except re.error as e:
                logger.warning(f"Invalid pattern {pattern_def.get('name')}: {e}")
                
        return findings
    
    def _semantic_scan(self, code_content: str) -> List[HeuristicFinding]:
        """Semantic similarity scanning using embeddings."""
        findings = []
        
        try:
            import torch
            
            # Get code lines with potential issues
            lines = code_content.split('\n')
            
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                    
                # Skip comments and strings
                if line.startswith('#') or line.startswith('"""'):
                    continue
                
                # Get embedding
                code_embedding = self._get_embedding(line)
                if code_embedding is None:
                    continue
                
                # Compare to known patterns
                for j, pattern_data in enumerate(VULNERABILITY_PATTERNS):
                    similarity = self._cosine_similarity(
                        code_embedding,
                        self.pattern_embeddings[j]
                    )
                    
                    if similarity > self.SIMILARITY_THRESHOLD:
                        finding = HeuristicFinding(
                            finding_type=pattern_data["type"],
                            severity=pattern_data["severity"],
                            evidence=line[:100],
                            line=i,
                            pattern=pattern_data["name"],
                            confidence=similarity
                        )
                        findings.append(finding)
                        
        except Exception as e:
            logger.warning(f"Semantic scan error: {e}")
            
        return findings
    
    def _deduplicate(self, findings: List[HeuristicFinding]) -> List[HeuristicFinding]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        
        for f in findings:
            key = (f.line, f.finding_type, f.pattern)
            if key not in seen:
                seen.add(key)
                unique.append(f)
            else:
                # Update confidence if higher
                for existing in unique:
                    if (existing.line == f.line and 
                        existing.finding_type == f.finding_type and
                        f.confidence > existing.confidence):
                        existing.confidence = f.confidence
        
        return unique
    
    def analyze_file(self, file_path: str) -> List[HeuristicFinding]:
        """Analyze a single file."""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            return self.analyze(content, file_path)
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return []


if __name__ == "__main__":
    analyzer = HeuristicAnalyzer()
    
    test_code = '''
import os
import subprocess
api_key = "my_secret_token_12345"
def run_cmd(cmd):
    subprocess.call(cmd, shell=True)
    os.popen(cmd)
'''
    findings = analyzer.analyze(test_code, "test.py")
    for f in findings:
        print(f"[{f.severity}] {f.finding_type} ({f.confidence:.2f}) at line {f.line}")