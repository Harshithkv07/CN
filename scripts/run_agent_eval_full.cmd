@echo off
rem Full incident-attribution / RAG-ablation evaluation: 10 alerts per class x 3 modes (~2.5 h on CPU).
cd /d "%~dp0.."
if not exist data\logs mkdir data\logs
start "HRT - Agent eval (full)" /min cmd /c ".venv\Scripts\python.exe -m hrt.cli -v eval agent >> data\logs\agent_full.log 2>&1"
