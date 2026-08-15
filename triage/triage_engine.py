import json
import pandas as pd
import os
import time
from datetime import datetime
from pyod.models.iforest import IForest

def process_and_export(records):
    df = pd.DataFrame(records)
    cols_to_keep = ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'duration', 'orig_bytes', 'resp_bytes']
    
    for col in cols_to_keep:
        if col not in df.columns:
            df[col] = 0.0

    df = df[cols_to_keep].copy()
    
    numeric_cols = ['duration', 'orig_bytes', 'resp_bytes']
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(float)
        
    features = ['id.resp_p', 'duration', 'orig_bytes', 'resp_bytes']
    X = df[features]
    
    try:
        clf = IForest(contamination=0.05, random_state=42)
        clf.fit(X)
        df['is_anomaly'] = clf.labels_
        df['anomaly_score'] = clf.decision_scores_
    except Exception as e:
        print(f"Skipping anomaly detection: {e}")
        return
        
    anomalies = df[df['is_anomaly'] == 1]
    if anomalies.empty:
        return
        
    # Group by id.orig_h
    grouped = anomalies.groupby('id.orig_h').agg(
        unique_ports_targeted=('id.resp_p', 'nunique'),
        total_flows=('id.resp_p', 'count')
    ).reset_index()
    
    grouped = grouped.rename(columns={'id.orig_h': 'source_ip'})
    grouped['alert_trigger_time'] = datetime.utcnow().isoformat()
    
    payload = grouped.to_dict(orient='records')
    
    with open('alert_payload.json', 'w') as f:
        json.dump(payload, f, indent=4)
        
    print(f"[{datetime.utcnow().isoformat()}] Exported {len(payload)} alerts to alert_payload.json")

def tail_log_and_process(filepath):
    while not os.path.exists(filepath):
        print(f"Waiting for {filepath} to be created...")
        time.sleep(2)
        
    with open(filepath, 'r') as f:
        # Seek to the end of the file
        f.seek(0, os.SEEK_END)
        print(f"Tailing {filepath} for new records...")
        
        accumulated_records = []
        
        while True:
            new_lines_read = False
            while True:
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        accumulated_records.append(data)
                        new_lines_read = True
                    except json.JSONDecodeError:
                        pass
            
            # Require at least some records to fit IForest properly
            if new_lines_read and len(accumulated_records) > 20:
                process_and_export(accumulated_records)
                # Keep sliding window of last 10,000 records
                if len(accumulated_records) > 10000:
                    accumulated_records = accumulated_records[-10000:]
                    
            time.sleep(1)

if __name__ == "__main__":
    filepath = '../telemetry/logs/conn.log'
    tail_log_and_process(filepath)
