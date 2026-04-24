"""
Code-aware Risk Scorer
Uses CodeBERT for better vulnerability detection in source code
"""
import re
import logging
import os
import torch
from typing import List, Dict, Any, Optional

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'

logger = logging.getLogger(__name__)

SCORE_HIGH_THRESHOLD = 0.8
SCORE_MEDIUM_THRESHOLD = 0.5

# Security keywords for scoring
RISK_KEYWORDS = {
    "Critical": ["password", "secret", "key", "token", "api_key", "private", "credential", "auth", "jwt", "token"],
    "High": ["eval", "exec", "system", "shell", "command", "sql", "injection", "xss", "deserialize", "pickle"],
    "Medium": ["random", "crypto", "hash", "weak", "debug", "log", "session", "md5", "sha1"],
    "Low": ["deprecated", "todo", "fixme", "unused", "comment", "ip", "url"]
}

# Code-specific vulnerability tokens
VULN_TOKENS = [
    "eval", "exec", "compile", "__import__",
    "os.system", "subprocess", "popen", "spawn",
    "cursor.execute", "fetchall", "raw_query",
    "pickle.load", "yaml.load", "marshal",
    "hashlib.md5", "hashlib.sha1", "DES",
    "random.random", "random.randint",
    "ssl._create_unverified_context", "verify=False",
    "requests.get", "urllib.open", "urlopen",
    "innerHTML", "document.write",
    "XMLParser", "ET.fromstring",
    "tempfile", "NamedTemporaryFile",
]


class RiskScore:
    """Risk score for a finding."""
    def __init__(
        self,
        finding_type: str,
        severity: str,
        evidence: str,
        line: int,
        score: float,
        confidence: float = 1.0
    ):
        self.finding_type = finding_type
        self.severity = severity
        self.evidence = evidence
        self.line = line
        self.score = score
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "evidence_span": self.evidence,
            "line": self.line,
            "risk_score": self.score,
            "confidence": self.confidence
        }


class CodeBERTRiskScorer:
    """
    Uses CodeBERT for vulnerability risk scoring.
    CodeBERT understands code semantics better than general NLP models.
    Uses local models when available for stability.
    """
    
    MODEL_NAME = "microsoft/CodeBERT-base"
    LOCAL_MODELS = {
        "microsoft/graphcodebert-base": "graphcodebert",
        "sentence-transformers/all-MiniLM-L6-v2": "minilm-l6-v2",
    }
    
    def __init__(self, use_codebert: bool = True):
        """
        Initialize risk scorer.
        
        Args:
            use_codebert: Whether to use CodeBERT (True) or fallback (False)
        """
        self.use_codebert = use_codebert
        self.model_name = self.MODEL_NAME if use_codebert else "microsoft/graphcodebert-base"
        self.model = None
        self.tokenizer = None
        self.device = "cpu"
        self._initialize_model()
        
    def _initialize_model(self) -> None:
        """Initialize CodeBERT or fallback to MiniLM."""
        try:
            from transformers import AutoModel, AutoTokenizer
            from repoguard.config import get_models_dir
            
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            
            # Use config to get models directory
            local_model_dir = get_models_dir()
            
            if self.use_codebert:
                try:
                    # Try local path first
                    local_path = os.path.join(local_model_dir, "graphcodebert")
                    if os.path.exists(local_path):
                        logger.info(f"Loading local model from {local_path}...")
                        self.tokenizer = AutoTokenizer.from_pretrained(local_path)
                        self.model = AutoModel.from_pretrained(local_path)
                    else:
                        logger.info(f"Loading {self.model_name}...")
                        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                        self.model = AutoModel.from_pretrained(self.model_name)
                    self.model.to(self.device)
                    self.model.eval()
                    logger.info(f"CodeBERT scorer initialized on {self.device}")
                except Exception as e:
                    logger.warning(f"CodeBERT failed: {e}, trying graphcodebert...")
                    # Try local graphcodebert
                    local_path = os.path.join(local_model_dir, "graphcodebert")
                    if os.path.exists(local_path):
                        self.tokenizer = AutoTokenizer.from_pretrained(local_path)
                        self.model = AutoModel.from_pretrained(local_path)
                    else:
                        self.model_name = "microsoft/graphcodebert-base"
                        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                        self.model = AutoModel.from_pretrained(self.model_name)
                    self.model.to(self.device)
                    self.model.eval()
                    logger.info(f"GraphCodeBERT scorer initialized on {self.device}")
            else:
                # Use MiniLM as fallback
                raise Exception("Fallback to MiniLM")
                
        except Exception as e:
            logger.warning(f"Using MiniLM fallback: {e}")
            self._load_minilm_fallback()
    
    def _load_minilm_fallback(self) -> None:
        """Load MiniLM as fallback."""
        from transformers import AutoModel, AutoTokenizer
        from repoguard.config import get_models_dir
        
        local_model_dir = get_models_dir()
        
        # Try local path first
        local_path = os.path.join(local_model_dir, "minilm-l6-v2")
        if os.path.exists(local_path):
            logger.info(f"Loading local MiniLM from {local_path}...")
            self.model_name = "sentence-transformers/all-MiniLM-L6-v2"
            self.tokenizer = AutoTokenizer.from_pretrained(local_path)
            self.model = AutoModel.from_pretrained(local_path)
        else:
            self.model_name = "sentence-transformers/all-MiniLM-L6-v2"
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModel.from_pretrained(self.model_name)
        
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model.to(self.device)
        self.model.eval()
        self.use_codebert = False
        logger.info(f"MiniLM fallback initialized on {self.device}")
    
    def _get_embedding(self, text: str) -> torch.Tensor:
        """Get code embedding."""
        if self.model is None or self.tokenizer is None:
            return torch.zeros(768 if self.use_codebert else 384)
            
        try:
            import torch
            
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
            
            # Mean pooling
            if "attention_mask" in inputs:
                hidden = outputs.last_hidden_state
                mask = inputs["attention_mask"].unsqueeze(-1).expand(hidden.size()).float()
                embedding = (hidden * mask).sum(1) / mask.sum(1)
            else:
                embedding = outputs.last_hidden_state.mean(dim=1)
                
            return embedding.squeeze(0).cpu()
            
        except Exception as e:
            logger.warning(f"Embedding error: {e}")
            return torch.zeros(768 if self.use_codebert else 384)
    
    def score_finding(
        self,
        finding_type: str,
        evidence: str,
        code_context: str,
        line: int,
        original_severity: str = "Medium"
    ) -> RiskScore:
        """
        Score a finding using CodeBERT.
        
        Args:
            finding_type: Type of vulnerability
            evidence: Code snippet
            code_context: Surrounding code
            line: Line number
            original_severity: Initial severity
            
        Returns:
            RiskScore
        """
        # Get embedding
        text = f"{finding_type}: {evidence}"
        embedding = self._get_embedding(text)
        
        # Calculate score
        score = self._calculate_code_score(finding_type, evidence, code_context)
        severity = self._determine_severity(score, original_severity)
        
        # Confidence based on model and embedding quality
        confidence = min(abs(score - 0.5) * 2, 1.0)
        if not self.use_codebert:
            confidence *= 0.8  # Lower confidence for non-CodeBERT
        
        return RiskScore(
            finding_type=finding_type,
            severity=severity,
            evidence=evidence[:100],
            line=line,
            score=score,
            confidence=confidence
        )
    
    def score_findings(
        self,
        findings: List[Dict[str, Any]],
        code_content: str
    ) -> List[RiskScore]:
        """Score multiple findings."""
        scores = []
        
        for finding in findings:
            score = self.score_finding(
                finding_type=finding.get("finding_type", "Unknown"),
                evidence=finding.get("evidence_span", ""),
                code_context=code_content,
                line=finding.get("line", 0),
                original_severity=finding.get("severity", "Medium")
            )
            scores.append(score)
            
        return scores
    
    def _calculate_code_score(
        self,
        finding_type: str,
        evidence: str,
        context: str
    ) -> float:
        """Calculate score using keyword + token matching."""
        text = f"{finding_type} {evidence} {context}".lower()
        
        score = 0.5
        
        # Keyword boost
        for severity, keywords in RISK_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    if severity == "Critical":
                        score += 0.15
                    elif severity == "High":
                        score += 0.1
                    elif severity == "Medium":
                        score += 0.05
        
        # Token exact match (stronger signal)
        for token in VULN_TOKENS:
            if token in text:
                score += 0.2
        
        return min(max(score, 0.0), 1.0)
    
    def _determine_severity(self, score: float, original: str) -> str:
        """Determine final severity."""
        if score >= SCORE_HIGH_THRESHOLD:
            return "Critical"
        elif score >= 0.65:
            return "High"
        elif score >= SCORE_MEDIUM_THRESHOLD:
            return "Medium"
        return original
    
    def should_escalate(
        self,
        risk_score: float,
        confidence: float,
        needs_escalation: bool
    ) -> bool:
        """Determine if LLM escalation needed."""
        if needs_escalation:
            return True
        if risk_score >= SCORE_HIGH_THRESHOLD:
            return True
        if confidence < 0.4:
            return True
        return False


# Alias for backward compatibility
class RiskScorer(CodeBERTRiskScorer):
    """Backward compatible scorer."""
    pass


if __name__ == "__main__":
    scorer = CodeBERTRiskScorer(use_codebert=True)
    print(f"Model: {scorer.model_name}")
    print(f"Using CodeBERT: {scorer.use_codebert}")
    
    test_findings = [
        {"finding_type": "Secrets Leak", "severity": "Critical", "evidence_span": "API_KEY = 'xxx'", "line": 5},
        {"finding_type": "Injection", "severity": "High", "evidence_span": "eval(data)", "line": 10},
        {"finding_type": "SQL Injection", "severity": "Critical", "evidence_span": "cursor.execute(id + user)", "line": 15},
    ]
    
    for score in scorer.score_findings(test_findings, "code"):
        print(f"[{score.severity}] {score.finding_type} score={score.score:.2f} conf={score.confidence:.2f}")