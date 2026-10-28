@echo off
rem Long LLM evaluations on the default model (llama3.2:3b), one after another. Logs: data\logs\queue_llama.log
cd /d "%~dp0.."
start "HRT - eval queue (llama)" /min cmd /c ".venv\Scripts\python.exe -m hrt.cli eval agent --modes rag_hier,no_rag > data\logs\queue_llama.log 2>&1 && .venv\Scripts\python.exe -m hrt.cli eval injection >> data\logs\queue_llama.log 2>&1"
