#!/usr/bin/env python3

import os
import json
import subprocess
import datetime
import socket
import glob
import secrets
import string
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests module not available. Data export functionality disabled.")


def load_env_vars() -> Dict[str, str]:
    """Load environment variables from /etc/default/invent-client"""
    env_vars = {}
    
    # Set defaults for testing
    env_vars['INVENT_DIR'] = '/tmp/invent'  # Use /tmp for testing
    env_vars['INVENT_RETENTION_DAYS'] = '30'
    
    return env_vars


def run_command(command: str, shell: bool = True) -> Optional[str]:
    """Run a shell command and return output"""
    try:
        result = subprocess.run(command, shell=shell, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except Exception as e:
        print(f"Error running command '{command}': {e}")
        return None


def discover_and_run_info_scripts(script_dir: str, env_vars: Dict[str, str]) -> Dict[str, Dict]:
    """Discover and run all info gathering scripts in the script directory"""
    results = {}
    
    if not os.path.exists(script_dir):
        print(f"Info scripts directory not found: {script_dir}")
        return results
    
    # Find all Python scripts in the info_scripts directory
    script_pattern = os.path.join(script_dir, "*.py")
    script_files = glob.glob(script_pattern)
    
    for script_path in sorted(script_files):
        script_name = os.path.basename(script_path)
        script_key = os.path.splitext(script_name)[0]  # Remove .py extension
        
        try:
            print(f"Running info script: {script_name}")
            
            # Prepare environment for the script
            env = os.environ.copy()
            env.update(env_vars)
            
            # Run the script and capture output
            cmd = [script_path]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env
            )
            
            if result.returncode == 0:
                try:
                    script_data = json.loads(result.stdout)
                    results[script_key] = script_data
                    print(f"Successfully gathered data from {script_name}")
                except json.JSONDecodeError as e:
                    print(f"Script {script_name} produced invalid JSON output")
                    results[script_key] = {"error": f"Invalid JSON output"}
            else:
                print(f"Script {script_name} failed with return code {result.returncode}")
                results[script_key] = {"error": f"Script execution failed"}
                
        except Exception as e:
            print(f"Error running script {script_name}: {e}")
            results[script_key] = {"error": str(e)}
    
    return results


def write_fact_file(fact_dir: str, filename: str, data: Dict) -> None:
    """Write structured data to a fact file"""
    try:
        os.makedirs(fact_dir, exist_ok=True)
        fact_path = os.path.join(fact_dir, filename)
        with open(fact_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Written fact file: {fact_path}")
    except Exception as e:
        print(f"Error writing fact file {filename}: {e}")


def main():
    """Main function"""
    # Load environment variables
    env_vars = load_env_vars()
    
    data_dir = os.path.join(env_vars['INVENT_DIR'], 'data')
    fact_dir = os.path.join(env_vars['INVENT_DIR'], 'facts')  # Use local directory for testing
    
    # Determine info_scripts directory (relative to this script)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    info_scripts_dir = os.path.join(script_dir, 'info_scripts')
    
    # Generate timestamp-based filename
    timestamp = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
    filename = os.path.join(data_dir, f"data-{timestamp}.json")
    
    print(f"Using info scripts directory: {info_scripts_dir}")
    print(f"Writing fact files to: {fact_dir}")
    
    # Discover and run all info gathering scripts
    print("Gathering system information using modular scripts...")
    info_results = discover_and_run_info_scripts(info_scripts_dir, env_vars)
    
    # Write fact files for each info type
    for script_key, script_data in info_results.items():
        if script_data and not script_data.get('error'):
            # Use script name as JSON filename (script_key already has .py removed)
            write_fact_file(fact_dir, f"{script_key}.json", script_data)
        else:
            print(f"Skipping fact file for {script_key} due to script error")
    
    print(f"\nCompleted! Check {fact_dir} for generated fact files.")


if __name__ == "__main__":
    main()
