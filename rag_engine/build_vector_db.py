import os
import chromadb
from llama_index.core import VectorStoreIndex, Document, StorageContext, Settings
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.vector_stores.chroma import ChromaVectorStore
from mitreattack.stix20 import MitreAttackData

def main():
    print("Setting up local embeddings (BAAI/bge-small-en-v1.5)...")
    Settings.embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5")

    print("Initializing ChromaDB...")
    db = chromadb.PersistentClient(path="./chroma_db")
    chroma_collection = db.get_or_create_collection("mitre_intel")

    print("Setting up StorageContext...")
    vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
    storage_context = StorageContext.from_defaults(vector_store=vector_store)

    print("Loading MITRE ATT&CK STIX data...")
    mitre_attack_data = MitreAttackData("data/enterprise-attack.json")
    techniques = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)

    print(f"Extracted {len(techniques)} techniques. Parsing into documents...")
    documents = []
    
    for technique in techniques:
        # Extract MITRE ID
        mitre_id = "Unknown"
        if technique.external_references:
            for ref in technique.external_references:
                if ref.source_name == "mitre-attack":
                    mitre_id = ref.external_id
                    break
        
        name = technique.name or ""
        description = technique.description or ""
        text = f"{name}\n\n{description}"
        
        doc = Document(
            text=text,
            metadata={
                "mitre_id": mitre_id,
                "name": name
            }
        )
        documents.append(doc)

    print(f"Embedding {len(documents)} documents into VectorStoreIndex...")
    index = VectorStoreIndex.from_documents(
        documents, 
        storage_context=storage_context,
        show_progress=True
    )
    print("Finished building vector database!")

if __name__ == "__main__":
    main()
