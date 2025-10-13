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


def gather_kernel_info() -> Dict[str, Dict[str, str]]:
    """Gather kernel information"""
    try:
        uname_output = run_command("uname -rvmo")
        if not uname_output:
            return {"running-kernel": {"error": "Could not get kernel info"}}
        
        # Parse uname output: version release machine os
        parts = uname_output.split()
        if len(parts) >= 4:
            return {
                "running-kernel": {
                    "kernel-release": parts[0],
                    "kernel-version": parts[1].replace('#', ''),
                    "machine": parts[2],
                    "operating-system": parts[3]
                }
            }
    except Exception as e:
        print(f"Error gathering kernel info: {e}", file=sys.stderr)
    
    return {"running-kernel": {"error": "Could not parse kernel info"}}


if __name__ == "__main__":
    result = gather_kernel_info()
    print(json.dumps(result, indent=2))
