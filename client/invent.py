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
    try:
        with open('/etc/default/invent-client', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key] = value.strip('"\'')
    except FileNotFoundError:
        print("Warning: /etc/default/invent-client not found")
    
    # Set defaults if not found in file
    env_vars.setdefault('INVENT_DIR', '/opt/invent')
    env_vars.setdefault('INVENT_RETENTION_DAYS', '30')
    
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


def gather_puppet_facts(filename: str) -> bool:
    """Gather facts using Puppet and save to file"""
    try:
        output = run_command("puppet facts --render-as json 2>/dev/null")
        if output:
            with open(filename, 'w') as f:
                facts = json.loads(output)
                json.dump(facts, f, indent=2)
            return True
    except Exception as e:
        print(f"Error gathering Puppet facts: {e}")
    
    return False


def cleanup_old_files(data_dir: str, retention_days: int) -> None:
    """Clean up old data files"""
    try:
        cutoff_time = datetime.datetime.now() - datetime.timedelta(days=retention_days)
        
        for file_path in glob.glob(os.path.join(data_dir, "data-*.json")):
            try:
                file_stat = os.stat(file_path)
                file_time = datetime.datetime.fromtimestamp(file_stat.st_mtime)
                
                if file_time < cutoff_time:
                    os.remove(file_path)
                    print(f"Removed old file: {file_path}")
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")
                
    except Exception as e:
        print(f"Error during cleanup: {e}")


def generate_password(length: int = 256) -> str:
    """Generate a random password"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))


def export_data(filename: str, export_endpoint: str) -> None:
    """Export data to inventory receiver endpoint"""
    if not HAS_REQUESTS:
        print("Cannot export data: requests module not available")
        return
        
    try:
        username = socket.getfqdn()
        pwfile = "/opt/invent/passwd"
        
        # Get or generate password
        if os.path.exists(pwfile):
            with open(pwfile, 'r') as f:
                password = f.read().strip()
        else:
            os.makedirs(os.path.dirname(pwfile), exist_ok=True)
            password = generate_password()
            with open(pwfile, 'w') as f:
                f.write(password)
        
        # Send data via HTTP POST
        url = f"{export_endpoint}/host/{username}"
        
        with open(filename, 'rb') as f:
            files = {'file': f}
            auth = (username, password)
            headers = {'accept': 'application/json'}
            
            response = requests.post(url, files=files, auth=auth, headers=headers)
            
            if response.status_code == 200:
                print(f"Successfully exported data to {url}")
            else:
                print(f"Failed to export data. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                
    except Exception as e:
        print(f"Error exporting data: {e}")


def main():
    """Main function"""
    # Load environment variables
    env_vars = load_env_vars()
    
    data_dir = os.path.join(env_vars['INVENT_DIR'], 'data')
    export_endpoint = env_vars.get('INVENT_EXPORT_ENDPOINT')
    fact_dir = "/var/lib/puppet/facts.d"
    retention_days = int(env_vars['INVENT_RETENTION_DAYS'])
    
    # Determine info_scripts directory (relative to this script)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    info_scripts_dir = os.path.join(script_dir, 'info_scripts')
    
    # Generate timestamp-based filename
    timestamp = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
    filename = os.path.join(data_dir, f"data-{timestamp}.json")
    latest = os.path.join(data_dir, "latest.json")
    
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
    
    # Create data directory and export facts
    os.makedirs(data_dir, exist_ok=True)
    
    if gather_puppet_facts(filename):
        # Create symlink to latest
        try:
            if os.path.exists(latest):
                os.remove(latest)
            os.symlink(filename, latest)
        except Exception as e:
            print(f"Error creating symlink: {e}")
    
    # Clean up old files
    cleanup_old_files(data_dir, retention_days)
    
    # Export data if endpoint is configured
    if export_endpoint and os.path.exists(filename):
        export_data(filename, export_endpoint)
    
    print(f"\nCompleted! Fact files written to {fact_dir}")


if __name__ == "__main__":
    main()
