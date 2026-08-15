import json
import chromadb
from llama_index.core import VectorStoreIndex, Settings
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.vector_stores.chroma import ChromaVectorStore

def main():
    # 1. Read the alert payload
    payload_path = "../triage/alert_payload.json"
    try:
        with open(payload_path, "r") as f:
            alerts = json.load(f)
    except FileNotFoundError:
        print(f"Could not find {payload_path}. Make sure the triage engine has generated it.")
        return
        
    if not alerts:
        print("No alerts found in payload.")
        return
        
    first_alert = alerts[0]
    unique_ports = first_alert.get("unique_ports_targeted", 0)
    total_flows = first_alert.get("total_flows", 0)
    
    # 2. Format query string
    query_str = f"Network scanning and reconnaissance targeting {unique_ports} unique ports across {total_flows} flows."
    print(f"Querying MITRE ATT&CK DB for:\n'{query_str}'\n")
    
    # 3. Setup embeddings
    Settings.embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5")
    
    # 4. Initialize ChromaDB
    db = chromadb.PersistentClient(path="./chroma_db")
    chroma_collection = db.get_collection("mitre_intel")
    
    # 5. Load vector store and index
    vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
    index = VectorStoreIndex.from_vector_store(vector_store)
    
    # 6. Retrieve
    retriever = index.as_retriever(similarity_top_k=3)
    nodes = retriever.retrieve(query_str)
    
    # 7. Print results
    print("--- Top 3 Retrieved MITRE Techniques ---")
    for i, node in enumerate(nodes, 1):
        print(f"\nResult {i}:")
        print(f"Metadata: {node.metadata}")
        print(f"Text Snippet: {node.text[:250]}...")

if __name__ == "__main__":
    main()
