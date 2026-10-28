@echo off
rem Re-run of the Qwen evals after accepting percent-style confidence. Log: data\logs\queue_qwen2.log
cd /d "%~dp0.."
set PY=.venv\Scripts\python.exe
set LOG=data\logs\queue_qwen2.log
set HRT_OLLAMA_MODEL=qwen2.5:3b
echo %TIME% qwen standard > %LOG%
%PY% -m hrt.cli eval agent --tag qwen --per-class 3 --modes rag_hier,no_rag >> %LOG% 2>&1
echo %TIME% qwen hard >> %LOG%
%PY% -m hrt.cli eval agent --hard --tag hard_qwen --per-class 3 --modes rag_hier,no_rag >> %LOG% 2>&1
echo %TIME% report >> %LOG%
%PY% -m hrt.cli report >> %LOG% 2>&1
echo %TIME% queue finished >> %LOG%
