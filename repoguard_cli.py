#!/usr/bin/env python3
"""RepoGuard CLI entry point."""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repoguard import RepoGuard
from repoguard.engine.aggregator import Reporter


def check_ollama() -> dict:
    """Check if Ollama is available and return model info."""
    try:
        import requests
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        if r.status_code == 200:
            return r.json()
        return None
    except:
        return None


def list_models(api_base: str = "http://localhost:11434") -> list:
    """Get list of available models from Ollama."""
    try:
        import requests
        r = requests.get(f"{api_base}/api/tags", timeout=5)
        if r.status_code == 200:
            return r.json().get("models", [])
        return []
    except Exception as e:
        print(f"Error fetching models: {e}")
        return []


def test_llm(api_base: str, model: str) -> bool:
    """Test LLM connection."""
    try:
        import requests
        payload = {"model": model, "messages": [{"role": "user", "content": "test"}], "stream": False}
        r = requests.post(f"{api_base}/api/chat", json=payload, timeout=30)
        return r.status_code == 200
    except Exception as e:
        print(f"Connection error: {e}")
        return False


def main():
    use_llm = False
    llm_api = "http://localhost:11434"
    llm_model = None  # Will be selected interactively
    export_prompts = None
    
    # Parse arguments
    args = sys.argv[1:]
    if "--llm" in args:
        use_llm = True
        args.remove("--llm")
    
    for i, arg in enumerate(args):
        if arg == "--api" and i + 1 < len(args):
            llm_api = args[i + 1]
            args.pop(i)
        elif arg == "--model" and i + 1 < len(args):
            llm_model = args[i + 1]
            args.pop(i)
        elif arg == "--export-prompts" and i + 1 < len(args):
            export_prompts = args[i + 1]
            args.pop(i)
    
# Check for help/version
    if len(args) == 0 or args[0] in ["-h", "--help", "help"]:
        print("""
╔═══════════════════════════════════════════════════════════╗
║                   RepoGuard CLI                         ║
╠═══════════════════════════════════════════════════════════╣
║ USAGE:                                           ║
║   repoguard scan <path>        Scan file or directory  ║
║   repoguard code '<code>'     Scan code string     ║
║                                                  ║
║ OPTIONS:                                         ║
║   --llm                        Enable LLM         ║
║   --api <url>                  Custom API URL     ║
║   --model <name>                Model name        ║
║   --export-prompts <dir>        Export prompts to file   ║
║                                                  ║
║ EXAMPLES:                                         ║
║   repoguard scan .                              ║
║   repoguard scan ./src --llm                   ║
║   repoguard scan . --llm --model qwen3.5:9b   ║
║   repoguard scan . --llm --export-prompts prompts/   ║
║   repoguard code 'eval(user_input)' --llm      ║
║                                                  ║
║ TIP: Use --export-prompts to save LLM prompts for   ║
║ external processing (e.g., upload to Claude,     ║
║ GPT-4, Gemini for better analysis).               ║
║                                                  ║
╚═══════════════════════════════════════════════════════════╝
""")
        sys.exit(0)
    
    command = args[0] if args else "help"
    
    if command == "scan":
        path = args[1] if len(args) > 1 else "."
        
        if use_llm:
            ollama_info = check_ollama()
            if not ollama_info:
                print("Warning: Ollama not available on localhost:11434")
                print("Falling back to non-LLM mode...")
                use_llm = False
            else:
                # Interactive model selection
                models = ollama_info.get("models", [])
                if not models:
                    print("Warning: No models found in Ollama")
                    use_llm = False
                else:
                    print("\n=== Available Models ===")
                    for i, m in enumerate(models):
                        name = m.get("name", m.get("model", "unknown"))
                        size_gb = m.get("size", 0) / 1e9
                        details = m.get("details", {})
                        params = details.get("parameter_size", "unknown")
                        print(f"  {i+1}. {name} ({params}, {size_gb:.1f}GB)")
                    
                    if llm_model:
                        # Validate user-specified model exists
                        valid = any(m.get("name") == llm_model or m.get("model") == llm_model for m in models)
                        if valid:
                            print(f"\n[LLM] Using specified model: {llm_model}")
                        else:
                            print(f"\nWarning: Model '{llm_model}' not found. Available:")
                            for m in models:
                                print(f"  - {m.get('name')}")
                            print("Using first available model.")
                            llm_model = models[0].get("name") or models[0].get("model")
                    else:
                        print("\n[LLM] Select model (enter number or press Enter for default):")
                        for m in models:
                            print(f"  - {m.get('name')}")
                        print("  - custom: enter model name manually")
                        choice = input("Choice [1]: ").strip()
                        if choice.isdigit() and 1 <= int(choice) <= len(models):
                            llm_model = models[int(choice)-1].get("name") or models[int(choice)-1].get("model")
                        elif choice.lower() == "custom":
                            llm_model = input("Model name: ").strip()
                        elif not choice:
                            llm_model = models[0].get("name") or models[0].get("model")
                        else:
                            llm_model = choice
                    
                    print(f"[LLM] Testing connection to {llm_model}...")
                    if test_llm(llm_api, llm_model):
                        print(f"[LLM] Connected to {llm_model}")
                    else:
                        print(f"[LLM] Could not connect, falling back...")
                        use_llm = False
                    use_llm = False
        
        guard = RepoGuard(
            use_llm=use_llm,
            llm_model=llm_model,
            llm_api_base=llm_api,
            export_prompts=export_prompts
        )
        
        if export_prompts:
            print(f"[LLM] Prompts will be exported to: {export_prompts}/")
        
        reporter = Reporter()
        
        if os.path.isfile(path):
            report = guard.scan_file(path)
        elif os.path.isdir(path):
            report = guard.scan_repository(path)
        else:
            print(f"Error: {path} not found")
            sys.exit(1)
        
        reporter.print_report(report)
        
        if use_llm and guard.llm_analyzer:
            print(f"\n[LLM Analysis Enabled: {llm_model}]")
        
        if os.environ.get("REPOGUARD_JSON"):
            print("\n--- JSON Output ---")
            print(json.dumps(report, indent=2))
        
        summary = report.get("summary", {})
        if summary.get("critical_count", 0) > 0:
            sys.exit(2)
        elif summary.get("high_count", 0) > 0:
            sys.exit(1)
        sys.exit(0)
    
    elif command == "code":
        if len(args) < 2:
            print("Usage: repoguard code '<code>'")
            sys.exit(1)
        
        code = args[1]
        
        guard = RepoGuard(
            use_llm=use_llm,
            llm_model=llm_model,
            llm_api_base=llm_api
        )
        
        report = guard.scan_code(code, "input.py")
        
        reporter = Reporter()
        reporter.print_report(report)
        
        if use_llm and guard.llm_analyzer:
            print(f"\n[LLM Analysis Enabled: {llm_model}]")
        
        sys.exit(0)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()