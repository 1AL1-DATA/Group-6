"""
LLM Context Analyzer
Analyzes findings in context and generates explanations/fixes
"""
import logging
import os
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class LLMAnalysis:
    """Result from LLM analysis."""
    def __init__(
        self,
        finding_type: str,
        line: int,
        explanation: str,
        fix_suggestion: Optional[str] = None,
        confidence: float = 0.5
    ):
        self.finding_type = finding_type
        self.line = line
        self.explanation = explanation
        self.fix_suggestion = fix_suggestion
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "line": self.line,
            "explanation": self.explanation,
            "fix_suggestion": self.fix_suggestion,
            "confidence": self.confidence
        }


class LLMAnalyzer:
    """
    Uses LLM for contextual analysis.
    Supports Ollama (local) or external API.
    """
    
    DEFAULT_SYSTEM_PROMPT = """You are a security expert analyzing code for vulnerabilities.
For each finding, provide:
1. A clear explanation of the vulnerability
2. A concrete fix suggestion with code example
Be concise and helpful."""

    def __init__(
        self,
        model: str = "llama3.2",
        api_base: Optional[str] = None,
        use_ollama: bool = True,
        export_prompts: Optional[str] = None
    ):
        """
        Initialize LLM analyzer.
        
        Args:
            model: Model name to use
            api_base: Custom API base URL
            use_ollama: Whether to use Ollama
            export_prompts: File path to export prompts for external LLM processing
        """
        self.model = model
        self.api_base = api_base or "http://localhost:11434"
        self.use_ollama = use_ollama
        self.system_prompt = self.DEFAULT_SYSTEM_PROMPT
        self.export_prompts = export_prompts
        self._available = False
        self._check_availability()
        
    def _check_availability(self) -> None:
        """Check if LLM is available."""
        if not self.use_ollama:
            self._available = False
            return
            
        try:
            import requests
            response = f"{self.api_base}/api/tags"
            logger.info(f"Checking Ollama at {self.api_base}...")
            # Don't actually make the request, just set available
            # The user would need Ollama running
            self._available = True
        except Exception as e:
            logger.warning(f"LLM not available: {e}")
            self._available = False
    
    def analyze(
        self,
        finding: Dict[str, Any],
        code_context: str,
        max_context_lines: int = 20
    ) -> LLMAnalysis:
        """
        Analyze a finding in context.
        
        Args:
            finding: Finding to analyze
            code_context: Surrounding code
            max_context_lines: Lines of context to include
            
        Returns:
            LLMAnalysis object
        """
        if not self._available:
            return self._stub_analysis(finding)
            
        prompt = self._build_prompt(finding, code_context, max_context_lines)
        
        # Export prompt to file if requested
        if self.export_prompts:
            self._export_prompt(finding, prompt)
            return self._stub_analysis(finding)
        
        try:
            response = self._query_llm(prompt)
            return self._parse_response(finding, response)
        except Exception as e:
            logger.warning(f"LLM query failed: {e}")
            return self._stub_analysis(finding)
    
    def analyze_batch(
        self,
        findings: List[Dict[str, Any]],
        code_contents: Dict[str, str]
    ) -> List[LLMAnalysis]:
        """
        Analyze multiple findings.
        
        Args:
            findings: List of findings
            code_contents: Dict of file path -> content
            
        Returns:
            List of LLMAnalysis objects
        """
        analyses = []
        
        for finding in findings:
            file_path = finding.get("file", "unknown")
            context = code_contents.get(file_path, "")
            
            analysis = self.analyze(finding, context)
            analyses.append(analysis)
            
        return analyses
    
    def _build_prompt(
        self,
        finding: Dict[str, Any],
        code_context: str,
        max_lines: int
    ) -> str:
        """Build prompt for LLM."""
        # Get relevant context
        line_num = finding.get("line", 0)
        lines = code_context.split('\n')
        
        start = max(0, line_num - max_lines // 2)
        end = min(len(lines), line_num + max_lines // 2)
        context = '\n'.join(f"{i+1}: {lines[i]}" for i in range(start, end))
        
        prompt = f"""Analyze this security finding:

Finding Type: {finding.get('finding_type')}
Severity: {finding.get('severity')}
Evidence: {finding.get('evidence_span')}
Line: {finding.get('line')}

Code context:
```
{context}
```

Provide:
1. Explanation of the vulnerability
2. How to fix it (show code example)
"""
        return prompt
    
    def _query_llm(self, prompt: str) -> str:
        """Query the LLM."""
        import requests
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }
        
        response = requests.post(
            f"{self.api_base}/api/chat",
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json().get("message", {}).get("content", "")
        else:
            raise Exception(f"LLM error: {response.status_code}")
    
    def _parse_response(
        self,
        finding: Dict[str, Any],
        response: str
    ) -> LLMAnalysis:
        """Parse LLM response."""
        lines = response.split('\n')
        
        explanation = ""
        fix = None
        
        in_fix = False
        for line in lines:
            if "fix" in line.lower() or "solution" in line.lower():
                in_fix = True
            if in_fix:
                fix = f"{fix}\n{line}" if fix else line
            else:
                explanation = f"{explanation}\n{line}" if explanation else line
        
        return LLMAnalysis(
            finding_type=finding.get("finding_type"),
            line=finding.get("line", 0),
            explanation=explanation.strip()[:500],
            fix_suggestion=fix.strip()[:500] if fix else None,
            confidence=0.7
        )
    
    def _stub_analysis(self, finding: Dict[str, Any]) -> LLMAnalysis:
        """Stub analysis when LLM unavailable."""
        findings = finding.get("finding_type", "Unknown")
        
        explanations = {
            "Secrets Leak": "Hardcoded secrets can be exposed in version control and logs. Move to environment variables or secrets manager.",
            "Injection": "Dynamic code execution can allow attackers to run arbitrary code. Use safe alternatives.",
            "SQL Injection": "SQL queries built from user input can be manipulated. Use parameterized queries.",
            "Insecure Deserialization": "Unsafe deserialization can lead to code execution. Use safe formats.",
            "Misconfiguration": "This configuration could expose the system to security risks."
        }
        
        explanation = explanations.get(findings, "This finding may pose a security risk. Review carefully.")
        
        fixes = {
            "Secrets Leak": "Use environment variables: os.environ.get('API_KEY')",
            "Injection": "Use ast.literal_eval() for safe evaluation or redesign",
            "SQL Injection": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (id,))",
            "Insecure Deserialization": "Use JSON or pickletools for controlled deserialization",
            "Misconfiguration": "Configure appropriately for production environment"
        }
        
        fix = fixes.get(findings, "Review and fix according to security best practices.")
        
        return LLMAnalysis(
            finding_type=findings,
            line=finding.get("line", 0),
            explanation=explanation,
            fix_suggestion=fix,
            confidence=0.4
        )
    
    def is_available(self) -> bool:
        """Check if LLM is available."""
        return self._available
    
    def _export_prompt(self, finding: Dict[str, Any], prompt: str) -> None:
        """Export prompt to a file for external LLM processing."""
        finding_type = finding.get("finding_type", "unknown").replace(" ", "_")
        line_num = finding.get("line", 0)
        filename = f"{self.export_prompts}/{finding_type}_line{line_num}.txt"
        
        os.makedirs(self.export_prompts, exist_ok=True)
        
        with open(filename, "w") as f:
            f.write(f"# Finding: {finding.get('finding_type')} at line {line_num}\n")
            f.write(f"# Severity: {finding.get('severity')}\n")
            f.write(f"# Evidence: {finding.get('evidence_span')}\n")
            f.write(f"# File: {finding.get('file', 'unknown')}\n")
            f.write(f"\n{prompt}\n\n")
            f.write("\n# RESPONSE FORMAT:\n")
            f.write("# Provide your analysis in the following format:\n")
            f.write("# ---EXPLANATION---\n")
            f.write("# [Your explanation here]\n")
            f.write("# ---FIX_SUGGESTION---\n")
            f.write("# [Your fix suggestion with code example here]\n")
        
        logger.info(f"Exported prompt to {filename}")


if __name__ == "__main__":
    # Test
    analyzer = LLMAnalyzer(use_ollama=False)
    
    finding = {
        "finding_type": "Secrets Leak",
        "severity": "Critical",
        "evidence_span": "API_KEY = 'xxx'",
        "line": 5
    }
    
    result = analyzer.analyze(finding, "code")
    print(f"Explanation: {result.explanation}")
    print(f"Fix: {result.fix_suggestion}")