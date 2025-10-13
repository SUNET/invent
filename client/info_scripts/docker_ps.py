#!/usr/bin/env python3

import subprocess
import json
import sys
from typing import Dict, List, Optional


def run_command(command: str, shell: bool = True) -> Optional[str]:
    """Run a shell command and return output"""
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except Exception as e:
        print(f"Error running command '{command}': {e}", file=sys.stderr)
        return None


def gather_docker_info() -> Dict[str, List[Dict]]:
    """Gather Docker container information"""
    docker_info = []
    
    try:
        # Check if docker is available
        if run_command("which docker") is None:
            return {"docker_ps": []}
        
        # Get running container IDs
        container_ids = run_command("docker ps -q")
        if not container_ids:
            return {"docker_ps": []}
        
        for container_id in container_ids.split('\n'):
            if container_id.strip():
                # Get container info
                container_json = run_command(f"docker ps --format '{{{{json . }}}}' --filter 'id={container_id.strip()}'")
                if container_json:
                    container_data = json.loads(container_json)
                    
                    # Get image ID
                    image_id = run_command(f"docker inspect --format '{{{{json .Image }}}}' {container_id.strip()}")
                    if image_id:
                        container_data["ImageId"] = json.loads(image_id)
                    
                    docker_info.append(container_data)
                    
    except Exception as e:
        print(f"Error gathering Docker info: {e}", file=sys.stderr)
    
    return {"docker_ps": docker_info}


if __name__ == "__main__":
    result = gather_docker_info()
    print(json.dumps(result, indent=2))
