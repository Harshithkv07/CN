import subprocess
import time
import os
import sys

ALERT_FILE = 'triage/alert_payload.json'

def main():
    print("[*] Starting ML Triage Engine as background daemon...")
    
    # We must run triage_engine.py from within the 'triage' directory 
    # so that its relative paths (like '../telemetry/logs/conn.log') resolve correctly.
    triage_python = os.path.abspath(os.path.join('triage', 'venv', 'Scripts', 'python.exe'))
    triage_process = subprocess.Popen([triage_python, 'triage_engine.py'], cwd='triage')
    
    last_mtime = 0
    if os.path.exists(ALERT_FILE):
        last_mtime = os.path.getmtime(ALERT_FILE)
        
    print("[*] Listening for anomaly generation...")
    
    try:
        while True:
            time.sleep(2)
            if os.path.exists(ALERT_FILE):
                current_mtime = os.path.getmtime(ALERT_FILE)
                if current_mtime > last_mtime:
                    last_mtime = current_mtime
                    print("[!] Anomaly Detected. Initializing SOC Agent...")
                    
                    # Trigger the RAG agent
                    # We must run soc_agent.py from within the 'rag_engine' directory 
                    # so that its relative paths (like './chroma_db') resolve correctly.
                    rag_python = os.path.abspath(os.path.join('rag_engine', 'venv', 'Scripts', 'python.exe'))
                    env = os.environ.copy()
                    
                    print("[*] Executing SOC Agent...")
                    result = subprocess.run(
                        [rag_python, 'soc_agent.py'],
                        cwd='rag_engine',
                        capture_output=True,
                        text=True,
                        env=env
                    )
                    
                    print(result.stdout)
                    if result.stderr:
                        print(f"Errors:\n{result.stderr}")
                    
                    print("[*] Listening for new anomalies...")
    except KeyboardInterrupt:
        print("\n[*] Shutting down orchestrator...")
        triage_process.terminate()

if __name__ == "__main__":
    main()
