# SCARF: Semantic Constraint-Aware Red-teaming Framework

Code for the AAAI 2026 submission "SCARF: Automated Red Teaming against LLM Agent Defenses via Semantic Constraints".

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Run basic experiment
python -m src.scarf_redteam --num_iterations 10 --api_key $LLM_API_KEY

# Run evaluation pipeline
python -m src.scarf_evaluation
```

## Structure

- `src/scarf_redteam.py` - Main SCARF algorithm implementation
- `src/scarf_evaluation.py` - Baselines and evaluation framework  
- `experiments/run_mcptox.sh` - Full experiment runner
- `data/` - Attack templates

## Baselines

1. Static - Original MCPTox attacks (no modification)
2. Paraphrase - Simple GPT-4o paraphrase of attack descriptions
3. Best-of-N - Generate N variants per attack, evaluate all
4. SCARF - Semantic constraint random search (ours)

## Requirements

- OpenAI-compatible API endpoint (keys set via LLM_API_KEY)
- Model: GPT-4o or equivalent for generation
- Evaluation: Local MCP environment (optional)
