@echo off
rem Start the live Tier-1 triage engine (tails data\zeek\conn.log) minimized.
cd /d "%~dp0.."
if not exist data\logs mkdir data\logs
start "HRT - Triage" /min cmd /c ".venv\Scripts\python.exe -m hrt.cli triage >> data\logs\triage.log 2>&1"
