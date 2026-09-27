@echo off
rem Run the live time-to-response benchmark (needs Docker lab, Ollama, orchestrator and triage running).
cd /d "%~dp0.."
if not exist data\logs mkdir data\logs
start "HRT - Live benchmark" /min cmd /c ".venv\Scripts\python.exe -m hrt.cli eval live >> data\logs\live.log 2>&1"
