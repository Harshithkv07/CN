import time
import subprocess
import os
import sys

ALERT_FILE = os.path.join('triage', 'alert_payload.json')

def main():
    print("[*] Starting Benchmark...")
    start_time = time.perf_counter()

    print("[*] Executing traffic simulation...")
    # Execute the bash script
    try:
        subprocess.run(["bash", "simulate_traffic.sh"], check=False)
    except FileNotFoundError:
        # Fallback if bash is not directly available in Windows path
        try:
            subprocess.run(["wsl", "bash", "simulate_traffic.sh"], check=False)
        except FileNotFoundError:
            print("[-] Error: 'bash' or 'wsl' not found. Cannot simulate traffic.")

    print("[*] Waiting for Anomaly Detection (Triage Engine)...")
    # Monitor alert_payload.json mtime to know when the triage engine fires
    if os.path.exists(ALERT_FILE):
        initial_mtime = os.path.getmtime(ALERT_FILE)
    else:
        initial_mtime = 0

    # Wait for triage engine to update the payload
    # Note: Triage engine must be running separately via hrt_orchestrator.py or manually.
    # Alternatively, we just poll for the file update.
    while True:
        if os.path.exists(ALERT_FILE):
            current_mtime = os.path.getmtime(ALERT_FILE)
            if current_mtime > initial_mtime:
                break
        time.sleep(0.5)

    print("[!] Anomaly detected! Triggering RAG/LLM Agent...")
    
    # Trigger SOC Agent directly to measure precise LLM execution time
    rag_python = os.path.abspath(os.path.join('rag_engine', 'venv', 'Scripts', 'python.exe'))
    env = os.environ.copy()
    
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

    end_time = time.perf_counter()
    ttm = end_time - start_time
    
    print(f"\n========================================")
    print(f"Total Time-to-Mitigation: {ttm:.2f} seconds")
    print(f"========================================\n")

if __name__ == "__main__":
    main()
