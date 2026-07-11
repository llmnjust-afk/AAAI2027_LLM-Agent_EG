#!/bin/bash
# SCARF Red-Teaming Framework - Full Experiment Runner
# Usage: bash experiments/run_mcptox.sh

set -e
cd /data/lab/scarf_redteam

export LLM_API_KEY="${LLM_API_KEY:?Set LLM_API_KEY environment variable}"

echo "=== SCARF: Automated Red Teaming for MCP Agent Defenses ==="
echo "Started at $(date)"

# Run evaluation pipeline
python3 -m src.scarf_evaluation

echo "=== Experiment completed at $(date) ==="

# Push to GitHub
cd /data/lab/scarf_redteam
if [ -d .git ]; then
    git add .
    git commit -m "Automated SCARF red-teaming results $(date -u)" || true
    git push origin main || echo "Push failed - run manually"
fi
