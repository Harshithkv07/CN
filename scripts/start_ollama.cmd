@echo off
rem Start the portable Ollama server (D:\Ollama) minimized, logging to D:\Ollama\serve*.log.
set OLLAMA_MODELS=D:\Ollama\models
set OLLAMA_HOST=127.0.0.1:11434
start "HRT - Ollama" /min cmd /c "D:\Ollama\app\ollama.exe serve >> D:\Ollama\serve.out.log 2>> D:\Ollama\serve.err.log"
