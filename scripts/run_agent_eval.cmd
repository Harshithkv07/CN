@echo off
rem Run the incident-attribution / RAG-ablation evaluation (needs Ollama + Docker; ~40 min on CPU).
rem --fast = 3 alerts per attack family x 3 modes (hierarchical RAG, flat RAG, no RAG).
cd /d "%~dp0.."
if not exist data\logs mkdir data\logs
start "HRT - Agent eval" /min cmd /c ".venv\Scripts\python.exe -m hrt.cli -v eval agent --fast >> data\logs\agent.log 2>&1"
