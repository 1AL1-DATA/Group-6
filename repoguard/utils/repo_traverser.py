"""
Repository Traversal Module
Reads target project files and filters irrelevant content.
"""
import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

logger = logging.getLogger(__name__)

DEFAULT_IGNORE_PATTERNS = {
    '.git', '.svn', '.hg',
    'node_modules', 'venv', 'env', '.venv', '__pycache__',
    'dist', 'build', '.egg-info',
    '.pytest_cache', '.tox', '.mypy_cache',
    'vendor', 'third_party',
    '.DS_Store', 'Thumbs.db',
    'package-lock.json', 'yarn.lock', 'poetry.lock',
    'requirements.txt', 'package.json'
}

DEFAULT_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx',
    '.java', '.go', '.rs', '.rb', '.php',
    '.cs', '.c', '.cpp', '.h', '.hpp',
    '.sh', '.bash', '.zsh',
    '.sql', '.yaml', '.yml', '.json',
    '.xml', '.toml', '.ini', '.cfg'
}


class RepositoryTraverser:
    """Traverses a repository and collects files for analysis."""
    
    def __init__(
        self,
        ignore_patterns: Optional[Set[str]] = None,
        extensions: Optional[Set[str]] = None,
        max_file_size: int = 1_000_000
    ):
        self.ignore_patterns = ignore_patterns or DEFAULT_IGNORE_PATTERNS
        self.extensions = extensions or DEFAULT_EXTENSIONS
        self.max_file_size = max_file_size
        
    def traverse(self, repo_path: str) -> List[Dict[str, Any]]:
        """
        Traverse repository and return list of files to analyze.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            List of dictionaries with file_path and content
        """
        repo_path = Path(repo_path)
        if not repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
            
        files = []
        
        for file_path in repo_path.rglob('*'):
            if not file_path.is_file():
                continue
                
            # Check if should ignore
            if self._should_ignore(file_path):
                continue
                
            # Check extension
            if file_path.suffix not in self.extensions:
                continue
                
            # Check file size
            try:
                if file_path.stat().st_size > self.max_file_size:
                    logger.warning(f"Skipping large file: {file_path}")
                    continue
            except OSError:
                continue
                
            # Read content
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                relative_path = file_path.relative_to(repo_path)
                files.append({
                    'path': str(relative_path),
                    'absolute_path': str(file_path),
                    'content': content,
                    'extension': file_path.suffix
                })
            except Exception as e:
                logger.warning(f"Could not read {file_path}: {e}")
                continue
                
        logger.info(f"Found {len(files)} files to analyze in {repo_path}")
        return files
    
    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored."""
        parts = path.parts
        for pattern in self.ignore_patterns:
            if pattern in parts:
                return True
        return False
    
    def get_changed_files(self, repo_path: str, diff: str) -> List[Dict[str, Any]]:
        """Get only changed files from a git diff."""
        changed_files = []
        
        for line in diff.split('\n'):
            if line.startswith('diff --git'):
                # Extract file path
                parts = line.split('b/')
                if len(parts) > 1:
                    file_path = parts[1].strip()
                    
        return changed_files


if __name__ == "__main__":
    # Quick test
    traverser = RepositoryTraverser()
    files = traverser.traverse(".")
    for f in files[:3]:
        print(f"Found: {f['path']}")