import sys
import os
from pathlib import Path
from pprint import pprint
from typing import Any

try:
    import yaml
except ImportError:
    print(
        "Invent hiera collector requires the PyYAML module\nInstall with: apt install python3-yaml",
        file=sys.stderr,
    )
    sys.exit(0)

__author__ = "lundberg"


# Parse known hiera files, common.yaml, group.yaml and local.yaml.
# Hopefully we can avoid reading the hiera config file as we have a mix of version 3 and 5 and the format differs
# quite a lot.


def parse_hiera_file(
    file_name: str, datadir: str = "/etc/hiera/data/"
) -> None | dict[str, Any]:
    if not datadir.endswith(os.sep):
        datadir += os.sep
    path = Path(datadir + file_name)
    if path.is_file():
        with open(path, "r") as f:
            return yaml.safe_load(f)
    else:
        return None


def main():
    result = {}
    hiera_content = {}
    # add files in reverse order of precedence
    # keys in common.yaml will be replaced by keys in group.yaml and so on
    known_hiera_files = ["common.yaml", "group.yaml", "local.yaml"]
    for file_name in known_hiera_files:
        data = parse_hiera_file(file_name)
        if data:
            hiera_content.update(data)

    # gather key/value pairs from hiera_content
    # keys starting with meta
    result.update(
        (key, value) for key, value in hiera_content.items() if key.startswith("meta_")
    )

    for_puppet = {"hiera_meta": result}
    pprint(for_puppet)


if __name__ == "__main__":
    main()
