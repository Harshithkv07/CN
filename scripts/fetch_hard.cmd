@echo off
rem Download the extra CICIDS2018 classes for the hard RAG ablation (about 100 MB, ~10 min).
cd /d "%~dp0.."
start "HRT - fetch-hard" /min cmd /c ".venv\Scripts\python.exe -m hrt.cli fetch-hard > data\logs\fetch_hard.log 2>&1"
