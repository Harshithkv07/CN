@echo off
rem Start the HRT-Agent orchestrator + dashboard (http://localhost:8000) minimized.
cd /d "%~dp0.."
if not exist data\logs mkdir data\logs
start "HRT - Orchestrator" /min cmd /c ".venv\Scripts\python.exe -m hrt.cli serve >> data\logs\serve.log 2>&1"
