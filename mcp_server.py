"""
RepoGuard MCP Server
Provides Model Context Protocol interface for AI agents
"""
import sys
import os
import json
from typing import Dict, Any, Optional

# Add paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repoguard import RepoGuard


class MCPHandler:
    """Handles MCP requests."""
    
    def __init__(self):
        self.guard = RepoGuard()
    
    def analyze_file(self, file_path: str, file_content: str) -> Dict[str, Any]:
        """
        MCP: Analyze a file.
        
        Args:
            file_path: Path to file
            file_content: Content of the file
            
        Returns:
            Analysis report
        """
        # If file_content provided, use it; otherwise read file
        if file_content:
            return self.guard.scan_code(file_content, os.path.basename(file_path))
        elif os.path.exists(file_path):
            return self.guard.scan_file(file_path)
        else:
            return {"error": f"File not found: {file_path}"}
    
    def analyze_code(self, code: str, filename: str = "code.py") -> Dict[str, Any]:
        """
        MCP: Analyze code string.
        
        Args:
            code: Code content
            filename: Filename
            
        Returns:
            Analysis report
        """
        return self.guard.scan_code(code, filename)
    
    def analyze_repository(self, repo_path: str) -> Dict[str, Any]:
        """
        MCP: Analyze repository.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            Analysis report
        """
        return self.guard.scan_repository(repo_path)


def main():
    """MCP server entry point."""
    import sys
    
    handler = MCPHandler()
    
    # Read request from stdin
    try:
        request = json.load(sys.stdin)
    except:
        print(json.dumps({"error": "Invalid JSON"}))
        sys.exit(1)
    
    method = request.get("method", "")
    params = request.get("params", {})
    
    if method == "analyze_file":
        result = handler.analyze_file(
            params.get("file_path", ""),
            params.get("file_content", "")
        )
    elif method == "analyze_code":
        result = handler.analyze_code(
            params.get("code", ""),
            params.get("filename", "code.py")
        )
    elif method == "analyze_repository":
        result = handler.analyze_repository(params.get("repo_path", "."))
    else:
        result = {"error": f"Unknown method: {method}"}
    
    print(json.dumps(result))


if __name__ == "__main__":
    main()