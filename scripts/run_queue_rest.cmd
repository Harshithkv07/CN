@echo off
rem Second queue (see queue_rest.cmd). Waits for run_queue_llama.cmd to finish first.
cd /d "%~dp0.."
start "HRT - eval queue (rest)" /min cmd /c "scripts\queue_rest.cmd"
