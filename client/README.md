# Invent Client - Modular System Information Gatherer

## Overview

The invent client has been refactored into a modular system where different types of system information are gathered by separate, independent scripts.

## Architecture

### Main Script: `invent.py`
- Discovers and runs all info gathering scripts
- Handles Puppet facts integration
- Manages data export and cleanup
- Writes to production directories (`/var/lib/puppet/facts.d`, `/opt/invent`)

### Info Scripts Directory: `info_scripts/`
All info gathering scripts are stored here. Each script outputs JSON data and the filename (without .py) becomes the fact file name.

## Current Info Scripts

| Script | Output File | Description |
|--------|-------------|-------------|
| `kernel.py` | `kernel.json` | Kernel version and system info |
| `packages.py` | `packages.json` | Installed packages (auto-detects package manager: apk, rpm, dpkg) |
| `docker_ps.py` | `docker_ps.json` | Running Docker containers |
| `network.py` | `network.json` | Network interfaces and routing |
| `system.py` | `system.json` | System stats (uptime, load, memory, disk) |

## Adding New Info Gatherers

To add a new type of system information:

1. Create a new Python script in `info_scripts/` directory
2. Make it executable: `chmod +x info_scripts/your_script.py`
3. Ensure it outputs valid JSON to stdout
4. The script will be automatically discovered and run

### Example Script Template

```python
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

def gather_your_info() -> Dict:
    """Gather your specific system information"""
    info = {}
    
    # Your info gathering logic here
    # ...
    
    return {"your_category": info}

if __name__ == "__main__":
    result = gather_your_info()
    print(json.dumps(result, indent=2))
```

## Usage

### Usage
```bash
sudo python3 invent.py
```
(Requires root for writing to system directories)

## Environment Variables

Scripts can access environment variables passed from the main script:
- `INVENT_DIR`: Base directory for data storage
- `INVENT_RETENTION_DAYS`: How long to keep data files
- `INVENT_EXPORT_ENDPOINT`: API endpoint for data export

## File Naming Convention

- Script file: `info_scripts/example.py`
- Output fact file: `example.json`
- The script name (without `.py`) becomes the JSON filename

This makes the relationship between scripts and outputs clear and predictable.
