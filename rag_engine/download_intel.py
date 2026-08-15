import os
import requests

def download_mitre_stix():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    output_path = os.path.join(os.path.dirname(__file__), "data", "enterprise-attack.json")
    
    print(f"Downloading MITRE ATT&CK STIX data from:\n{url}")
    
    # Download the JSON file
    response = requests.get(url)
    response.raise_for_status()
    
    # Save it to the data directory
    with open(output_path, "wb") as f:
        f.write(response.content)
        
    file_size_mb = len(response.content) / (1024 * 1024)
    print(f"Successfully downloaded and saved {file_size_mb:.2f} MB to {output_path}")

if __name__ == "__main__":
    download_mitre_stix()
