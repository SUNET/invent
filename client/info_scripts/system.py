#!/usr/bin/env python3

import subprocess
import json
import sys
import os
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


def gather_system_info() -> Dict[str, Dict]:
    """Gather basic system information"""
    system_info = {}
    
    try:
        # Get uptime
        uptime = run_command("uptime -p")
        if uptime:
            system_info["uptime"] = uptime
        
        # Get load average
        loadavg = run_command("cat /proc/loadavg")
        if loadavg:
            parts = loadavg.split()
            if len(parts) >= 3:
                system_info["load_average"] = {
                    "1min": parts[0],
                    "5min": parts[1],
                    "15min": parts[2]
                }
        
        # Get memory info
        meminfo = run_command("cat /proc/meminfo")
        if meminfo:
            memory = {}
            for line in meminfo.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    memory[key.strip()] = value.strip()
            system_info["memory"] = memory
        
        # Get disk usage for root filesystem
        df_output = run_command("df -h /")
        if df_output:
            lines = df_output.split('\n')
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 6:
                    system_info["root_disk"] = {
                        "filesystem": parts[0],
                        "size": parts[1],
                        "used": parts[2],
                        "available": parts[3],
                        "use_percent": parts[4],
                        "mount_point": parts[5]
                    }
                    
    except Exception as e:
        print(f"Error gathering system info: {e}", file=sys.stderr)
        system_info["error"] = str(e)
    
    return {"system": system_info}


if __name__ == "__main__":
    result = gather_system_info()
    print(json.dumps(result, indent=2))
