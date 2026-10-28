@echo off
rem Waits for run_queue_llama.cmd to finish, then runs: hard-class ablation (llama), the second model
rem (qwen2.5:3b) on the standard and hard sets, and finally the report. Log: data\logs\queue_rest.log
cd /d "%~dp0.."
set PY=.venv\Scripts\python.exe
set LOG=data\logs\queue_rest.log
echo %TIME% waiting for the first queue >> %LOG%

:wait_first
findstr /c:"injection.json" data\logs\queue_llama.log >nul 2>&1 && goto first_done
ping -n 31 127.0.0.1 >nul
goto wait_first

:first_done
echo %TIME% first queue done >> %LOG%
:wait_hard
if exist data\cicids2018\cicids_hard.parquet goto run_hard
ping -n 31 127.0.0.1 >nul
goto wait_hard

:run_hard
echo %TIME% llama hard ablation >> %LOG%
%PY% -m hrt.cli eval agent --hard --tag hard --modes rag_hier,no_rag >> %LOG% 2>&1

:wait_qwen
curl -s http://127.0.0.1:11434/api/tags | findstr /c:"qwen2.5:3b" >nul 2>&1 && goto run_qwen
ping -n 61 127.0.0.1 >nul
goto wait_qwen

:run_qwen
set HRT_OLLAMA_MODEL=qwen2.5:3b
echo %TIME% qwen standard >> %LOG%
%PY% -m hrt.cli eval agent --tag qwen --per-class 5 --modes rag_hier,no_rag >> %LOG% 2>&1
echo %TIME% qwen hard >> %LOG%
%PY% -m hrt.cli eval agent --hard --tag hard_qwen --per-class 3 --modes rag_hier,no_rag >> %LOG% 2>&1
set HRT_OLLAMA_MODEL=

echo %TIME% building report >> %LOG%
%PY% -m hrt.cli report >> %LOG% 2>&1
echo %TIME% queue finished >> %LOG%
