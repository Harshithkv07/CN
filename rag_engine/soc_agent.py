import json
import chromadb
from llama_index.core import VectorStoreIndex, Settings, PromptTemplate
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.vector_stores.chroma import ChromaVectorStore
import os
from llama_index.llms.gemini import Gemini
from sandbox_validator import validate_rule

def main():
    # Initialize the LLM
    if "GOOGLE_API_KEY" not in os.environ:
        print("Error: GOOGLE_API_KEY environment variable not set.")
        return
        
    llm = Gemini(model="models/gemini-1.5-flash")

    # Define prompt template
    prompt_template_str = 'You are an autonomous Level-1 SOC Analyst. Based on the following network alert and MITRE ATT&CK context, generate a mitigation strategy. Output ONLY a valid JSON object with three keys: incident_summary (string), mitre_tactic (string), and iptables_rule (a string containing an iptables command to DROP traffic from the attacking Source IP). Do not include markdown formatting or explanations outside the JSON. For your first attempt, intentionally generate a syntactically invalid iptables rule (e.g., missing the -A flag). Context: {context_str}. Alert: {query_str}'
    prompt_template = PromptTemplate(prompt_template_str)

    # Read the alert payload
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
    
    # Query string for retrieval (from test_retrieval.py)
    retrieval_query_str = f"Network scanning and reconnaissance targeting {unique_ports} unique ports across {total_flows} flows."
    
    # Setup embeddings
    Settings.embed_model = HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5")
    
    # Initialize ChromaDB
    db = chromadb.PersistentClient(path="./chroma_db")
    chroma_collection = db.get_collection("mitre_intel")
    
    # Load vector store and index
    vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
    index = VectorStoreIndex.from_vector_store(vector_store)
    
    # Retrieve top 3 relevant techniques
    retriever = index.as_retriever(similarity_top_k=3)
    nodes = retriever.retrieve(retrieval_query_str)
    
    # Extract .text and combine into context_str
    context_str = "\n\n".join([node.text for node in nodes])

    # Format query_str as the stringified alert
    query_str = json.dumps(first_alert)
    
    # Format the PromptTemplate
    formatted_prompt = prompt_template.format(context_str=context_str, query_str=query_str)

    MAX_RETRIES = 3
    for attempt in range(MAX_RETRIES):
        print(f"\n--- Attempt {attempt + 1} ---")
        response = llm.complete(formatted_prompt)
        
        try:
            # Clean up the response text in case it has markdown code blocks
            response_text = response.text.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            result_json = json.loads(response_text)
            iptables_cmd = result_json.get("iptables_rule")
            
            if not iptables_cmd:
                print("Error: 'iptables_rule' key not found in JSON.")
                formatted_prompt += "\n\nThe generated JSON was missing the 'iptables_rule' key. Please include it."
                continue

            print(f"Testing rule: {iptables_cmd}")
            is_valid, error_string = validate_rule(iptables_cmd)
            
            if is_valid:
                print("Rule validated successfully")
                print("Final JSON:")
                print(json.dumps(result_json, indent=2))
                break
            else:
                print(f"Validation failed: {error_string}")
                formatted_prompt += f"\n\nThe generated iptables rule failed syntax validation with the following error: {error_string}. Please correct the syntax and output a new JSON mitigation."
                
        except json.JSONDecodeError as e:
            print(f"JSON Parse Error: {e}")
            print(f"Raw Output: {response.text}")
            formatted_prompt += "\n\nThe generated output was not valid JSON. Please output ONLY valid JSON without markdown formatting."

if __name__ == "__main__":
    main()
