# RepoGuard - Process Flow

## Setup (Conda)

```bash
cd Group-6
conda env create -f environment.yml
conda activate group6
```

```mermaid
flowchart TD
    Start([RepoGuard Start]) --> Input{Input Type}
    
    Input --> |File| FilePath[File Path]
    Input --> |Code| CodeStr[Code String]
    Input --> |Repository| RepoPath[Repository]
    
    FilePath --> Traverse
    RepoPath --> Traverse
    CodeStr --> Direct[Direct Analysis]
    
    subgraph S1["Stage 1: Discovery"]
        Traverse --> Scan[Scan Directory]
        Scan --> Filter[Filter: node_modules, .git]
        Filter --> Collect[Collect Files]
    end
    
    subgraph S2["Stage 2: Analysis"]
        Collect --> Rules[Rules Engine]
        Direct --> Rules
        
        subgraph R["Regex (50+)"]
            Rules --> Regex1[Pattern Match]
        end
        
        subgraph H["Heuristics (Semantic)"]
            Rules --> Embed[Get Embedding]
            Embed --> Sim[Compare Similarity]
            Sim --> |Score>0.55| Found[Finding]
        end
        
        Regex1 --> C1[Merge Results]
        Found --> C1
        C1 --> Classify[Severity Lookup]
        
        subgraph C["Classification"]
            Classify --> Crit[CRITICAL: RCE]
            Classify --> High[HIGH: Impact]
            Classify --> Med[MEDIUM: Partial]
            Classify --> Low[LOW: Minor]
        end
        
        Classify --> Context[Context Validator]
        
        subgraph FP["False Positive Filter"]
            Context --> VulnSig[Pattern Check]
            Context --> Source[Source Tracking]
            Context --> Type[Type Logic]
            VulnSig --> |Signal| Filter[Keep]
            Source --> |Trusted| Reduce[Reduce]
            Filter --> Risk[RScorer]
        end
        
        Risk --> LLM{LLM Escalate?}
        LLM --> |High| LLMAn[LLM Analysis]
        LLM --> |Low| Skip[Skip]
    end
    
    subgraph S3["Stage 3: Output"]
        LLMAn --> Agg[Aggregate]
        Skip --> Agg
        Agg --> Merge[Merge & Dedupe]
        Merge --> Report[Generate Report]
    end
    
    Report --> Out[JSON/CLI/SARIF]
    
    style Start fill:#1a1a2e,color:#fff
    style Crit fill:#dc2626,color:#fff
    style High fill:#ea580c,color:#fff
    style Med fill:#ca8a04,color:#fff
    style Low fill:#16a34a,color:#fff
```

## Pipeline Summary

### Stage 1: File Discovery
- Traverse repository
- Filter ignore patterns (node_modules, .git, etc.)
- Collect code files (.py, .js, .php, etc.)

### Stage 2: Multi-Stage Analysis

**2a. Rules Engine** (Deterministic)
- 10-15 regex patterns
- Fast, precise detection

**2b. Heuristic Analyzer** (Semantic)
- 50+ regex patterns
- 60+ semantic patterns with CodeBERT/MiniLM
- Similarity scoring

**2c. Severity Classification**
- CRITICAL: Direct RCE, credentials exposed
- HIGH: SQLi, command injection, path traversal
- MEDIUM: XSS, weak crypto, IDOR
- LOW: Debug mode, info disclosure
- POTENTIAL: Needs manual review

**2d. Context Validation** (False Positive Filter)
- Check vulnerability signals
- Track data source (user vs trusted)
- Type-specific logic

**2e. Risk Scoring**
- Embedding similarity
- Keyword boosting

**2f. LLM Analysis** (Optional)
- Only for high-risk findings
- Explanations and fix suggestions

### Stage 3: Aggregation & Output
- Merge findings from all stages
- Deduplicate by line/type
- Sort by severity
- Output: JSON, CLI, SARIF