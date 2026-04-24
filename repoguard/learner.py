"""
RepoGuard Learner - RL Training Loop
Trains a small model on vulnerability findings for improved detection
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any
from repoguard.config import get_install_dir, get_models_dir


class VulnerabilityDataset:
    """Dataset for training on vulnerability findings."""
    
    def __init__(self):
        self.findings = []
    
    def add_finding(self, finding: Dict, code_context: str, label: int):
        """Add finding to dataset. label: 1=vulnerable, 0=safe."""
        self.findings.append({
            "finding_type": finding.get("finding_type"),
            "severity": finding.get("severity"),
            "evidence": finding.get("evidence_span"),
            "code": code_context,
            "label": label
        })
    
    def save(self, path: str = None):
        """Save dataset."""
        if path is None:
            path = get_install_dir() / "data" / "training_data.json"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.findings, f, indent=2)
        return path
    
    def load(self, path: str = None):
        """Load dataset."""
        if path is None:
            path = get_install_dir() / "data" / "training_data.json"
        if os.path.exists(path):
            with open(path, 'r') as f:
                self.findings = json.load(f)
        return self.findings


class LearnerLLM:
    """RL-based learner using Ollama."""
    
    DEFAULT_MODEL = "tinyllama:1.1b"
    
    def __init__(self, base_model: str = None, api_base: str = "http://localhost:11434"):
        self.base_model = base_model or self.DEFAULT_MODEL
        self.api_base = api_base
        self.dataset = VulnerabilityDataset()
        self.is_trained = False
        
        # Load existing data
        if os.path.exists(get_install_dir() / "data" / "training_data.json"):
            self.dataset.load()
            self.is_trained = len(self.dataset.findings) > 0
    
    def learn_from_scan(self, report: Dict, code: str):
        """Learn from scan results."""
        findings = report.get("findings", [])
        for f in findings:
            self.dataset.add_finding(f, code, label=1)
        self.is_trained = len(self.dataset.findings) > 0
    
    def train(self) -> bool:
        """Save training data."""
        if self.dataset.findings:
            self.dataset.save()
            print(f"Training data: {len(self.dataset.findings)} examples")
            return True
        return False
    
    def test_knowledge(self, test_code: str) -> Dict:
        """Test learner's knowledge on new code."""
        from repoguard import RepoGuard
        
        baseline = RepoGuard(use_llm=False)
        baseline_report = baseline.scan_code(test_code, "test.py")
        
        findings_summary = ""
        for f in self.dataset.findings[:5]:
            findings_summary += f"- {f.get('finding_type')}: {f.get('evidence', '')[:50]}\n"
        
        prompt = f"""Using trained knowledge, analyze:

Code:
{test_code}

Known patterns:
{findings_summary}

Is vulnerable? Explain."""

        analysis = self._query(prompt)
        
        return {
            "baseline_findings": baseline_report["summary"]["total_findings"],
            "learner_analysis": analysis.get("explanation", "")[:300],
            "model": self.base_model,
            "trained": self.is_trained,
            "examples": len(self.dataset.findings)
        }
    
    def _query(self, prompt: str) -> Dict:
        """Query the model."""
        try:
            import requests
            payload = {
                "model": self.base_model,
                "messages": [
                    {"role": "system", "content": "You are a security expert."},
                    {"role": "user", "content": prompt}
                ],
                "stream": False
            }
            response = requests.post(f"{self.api_base}/api/chat", json=payload, timeout=60)
            if response.status_code == 200:
                content = response.json().get("message", {}).get("content", "")
                return {"explanation": content[:500], "fix": ""}
        except Exception as e:
            return {"explanation": f"Error: {e}"}
        return {"explanation": "Model unavailable"}
    
    def is_available(self) -> bool:
        """Check if Ollama is available."""
        try:
            import requests
            r = requests.get(f"{self.api_base}/api/tags", timeout=2)
            return r.status_code == 200
        except:
            return False


def run_rl_cycle(code_to_scan: str, model_name: str = "tinyllama:1.1b", iterations: int = 3) -> Dict:
    """Run RL cycle: scan -> learn."""
    from repoguard import RepoGuard
    
    results = {"iterations": iterations, "findings_history": [], "model": None}
    
    learner = LearnerLLM(base_model=model_name)
    
    for i in range(iterations):
        print(f"=== RL Iteration {i+1}/{iterations} ===")
        guard = RepoGuard(use_llm=False)
        report = guard.scan_code(code_to_scan, "input.py")
        count = report["summary"]["total_findings"]
        results["findings_history"].append(count)
        print(f"Findings: {count}")
        
        if count > 0:
            learner.learn_from_scan(report, code_to_scan)
    
    if learner.is_trained:
        learner.train()
    
    results["model"] = learner
    return results


if __name__ == "__main__":
    test_code = """import os
os.system(user_input)"""
    
    results = run_rl_cycle(test_code, iterations=1)
    print(f"Findings: {results['findings_history']}")