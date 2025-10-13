#!/usr/bin/env python3

import subprocess
import json
import sys
from typing import Dict, Optional


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


def gather_network_info() -> Dict[str, Dict]:
    """Gather network interface information"""
    network_info = {}
    
    try:
        # Get network interfaces
        ip_output = run_command("ip -j addr show")
        if ip_output:
            try:
                interfaces = json.loads(ip_output)
                network_info["interfaces"] = interfaces
            except json.JSONDecodeError:
                # Fallback to simple format if JSON not available
                ip_output = run_command("ip addr show")
                network_info["interfaces_text"] = ip_output
        
        # Get routing information
        route_output = run_command("ip route show")
        if route_output:
            network_info["routes"] = route_output.split('\n')
        
        # Get hostname
        hostname = run_command("hostname -f")
        if hostname:
            network_info["hostname"] = hostname
            
    except Exception as e:
        print(f"Error gathering network info: {e}", file=sys.stderr)
        network_info["error"] = str(e)
    
    return {"network": network_info}


if __name__ == "__main__":
    result = gather_network_info()
    print(json.dumps(result, indent=2))
