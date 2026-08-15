import docker
import json

def validate_rule(iptables_cmd):
    client = docker.from_env()
    try:
        client.containers.run(
            'alpine', 
            command=f'sh -c "apk add --no-cache iptables && {iptables_cmd}"', 
            remove=True, 
            cap_add=['NET_ADMIN']
        )
        return True, "Success"
    except docker.errors.ContainerError as e:
        stderr_msg = e.stderr.decode('utf-8') if e.stderr else str(e)
        return False, stderr_msg.strip()
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

if __name__ == "__main__":
    test_cases = [
        "iptables -A INPUT -s 172.18.0.3 -j DROP",
        "iptables -DROP 172.18.0.3"
    ]
    
    for idx, rule in enumerate(test_cases, 1):
        print(f"--- Test Case {idx} ---")
        print(f"Rule: {rule}")
        success, message = validate_rule(rule)
        print(f"Valid: {success}")
        print(f"Message: {message}\n")
