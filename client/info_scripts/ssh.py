#!/usr/bin/env python3
import glob
import os
from pprint import pprint


def parse_sshd_config(filepath="/etc/ssh/sshd_config") -> dict[str, str]:
    """Parses the given sshd configuration file and returns the set values.

    :arg filepath: Path of the configuration file to be parsed, default: /etc/ssh/sshd_config

    :return: Dictionary of set values.
    """
    result = {}
    if not os.path.exists(filepath):
        return result

    # Now read line by line
    with open(filepath) as fobj:
        for line in fobj:
            line = line.strip()
            # now just in case tab character was used, replace it
            line = line.replace("\t", " ")
            key, _, value = line.partition(" ")
            if value and not key.startswith("#"):  # Means we have a key and value
                result[key] = value.strip()
    # we are done
    return result


def main():
    final_result = {}
    # first we gather data from main configuration file
    main_data = parse_sshd_config()
    # Now we need to find any included configuration files
    # and parse them for other updates
    if "Include" in main_data:
        path = main_data["Include"]
        files = glob.glob(path)
        files.sort()  # Because they maybe numbered inclusion order
        for file in files:
            output = parse_sshd_config(file)
            final_result.update(output)
    # Now update it with main file's output
    final_result.update(main_data)
    for_puppet = {"sshd_config": final_result}
    pprint(for_puppet)


if __name__ == "__main__":
    main()
