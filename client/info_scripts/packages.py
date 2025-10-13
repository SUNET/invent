#!/usr/bin/env python3

import subprocess
import json
import sys
import re
from typing import List, Dict, Optional


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


def detect_package_manager() -> str:
    """Detect the available package manager"""
    try:
        # Check for apk (Alpine)
        if run_command("which apk"):
            return 'apk'
        
        # Check for rpm (RedHat, CentOS, Fedora, etc.)
        elif run_command("which rpm"):
            return 'rpm'
        
        # Check for dpkg (Debian, Ubuntu, etc.)
        elif run_command("which dpkg"):
            return 'dpkg'
        
        # If no known package manager found
        return 'unknown'
        
    except Exception as e:
        print(f"Error detecting package manager: {e}", file=sys.stderr)
        return 'unknown'


def gather_packages() -> List[Dict[str, str]]:
    """Gather package information based on available package manager"""
    packages = []
    package_manager = detect_package_manager()
    
    try:
        if package_manager == 'apk':
            output = run_command("apk list -q")
            if output:
                for line in output.split('\n'):
                    if line.strip():
                        # Parse alpine package format
                        parts = line.split()
                        if len(parts) >= 1:
                            name_version = parts[0]
                            # Split on first digit occurrence
                            match = re.match(r'^([^-]+)-(.+)$', name_version)
                            if match:
                                name, version = match.groups()
                                packages.append({"name": name, "version": version})
        
        elif package_manager == 'rpm':
            output = run_command("rpm -qa")
            if output:
                for line in output.split('\n'):
                    if line.strip():
                        # Parse RPM format
                        match = re.match(r'^(.+)-([^-]+)-([^-]+)$', line.strip())
                        if match:
                            name, version, release = match.groups()
                            packages.append({"name": name, "version": f"{version}-{release}"})
        
        elif package_manager == 'dpkg':
            output = run_command("dpkg-query -W")
            if output:
                for line in output.split('\n'):
                    if line.strip():
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            packages.append({"name": parts[0], "version": parts[1]})
        
        else:
            packages = [{"package_manager": package_manager, "status": "unsupported"}]
            
    except Exception as e:
        print(f"Error gathering packages: {e}", file=sys.stderr)
        packages = [{"error": str(e)}]
    
    return packages


if __name__ == "__main__":
    # Auto-detect package manager and gather packages
    packages = gather_packages()
    result = {"packages": packages}
    print(json.dumps(result, indent=2))
