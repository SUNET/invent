#!/usr/bin/env python3
import argparse
import json
import subprocess


def run_command(command: list[str]) -> tuple:
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.communicate()


def run_command_in_image(image: str, commands: list[str]) -> tuple:
    (id, _) =  run_command(["docker", "run", "-d", image, "sleep", "30"])
    cid = id.decode().strip()
    result = run_command(["docker", "exec", cid] + commands)
    (_,_) = run_command(["docker", "kill", cid])
    return result



def get_os_for_image(image: str) -> str:
    (stdout, _) = run_command_in_image(image, ["cat", "/etc/os-release"])
    hash = dict()
    for line in stdout.decode().split('\n'):
        (name, var) = line.partition("=")[::2]
        hash[name.strip().strip('"')] = var.strip().strip('"')
    if "PRETTY_NAME" in hash:
        if hash["PRETTY_NAME"] == "Distroless":
            return "distroless"
    return hash["ID"]


def parse_packages(provider: str, input: str) -> list[dict]:
    output = list()
    object_distroless = dict()
    for line in input.split('\n'):
        if len(line) > 0:
            object = dict()
            object["provider"] = provider
            match provider:
                case "alpine":
                    first_pass = line.split(' ')[0]
                    second_pass = first_pass.split('-')
                    package = second_pass[0]
                    version =  "-".join(second_pass[1:])
                case "centos":
                    first_pass = line.split(' ')[0]
                    second_pass = first_pass.split('-')
                    package = second_pass[0]
                    version =  "-".join(second_pass[1:])
                case "debian":
                    package, version = line.split('\t')
                case "distroless":
                    key, value = line.split(':')
                    if key.strip() == "Package":
                        del object_distroless
                        object_distroless = dict()
                        object_distroless["provider"] = "debian"
                        object_distroless["package"] = value.strip()
                    else:
                        object_distroless["version"] = value.strip()
                        output.append(object_distroless)
                case "fedora":
                    first_pass = line.split(' ')[0]
                    second_pass = first_pass.split('-')
                    package = second_pass[0]
                    version =  "-".join(second_pass[1:])
                case "pip":
                    package, version = line.split('==')
                case "ubuntu":
                    package, version = line.split('\t')
            if provider != "distroless":
                object["package"] = package
                object["version"] = version 
                output.append(object)
    return output

def get_inspect_data(image: str) -> list[dict]:
    (output, _) = run_command(["docker", "image", "inspect", image])
    return json.loads(output.decode())

def get_packages(image: str) -> list[dict]:
    os = get_os_for_image(image)
    command = list()
    result = list()
    match os:
        case "alpine":
            command = ["apk", "list", "-q"]
        case "centos":
            command =  ["rpm", "-qa"]
        case "debian":
            command = ["dpkg-query", "-W"]
        case "distroless":
            command = ["sh", "-c",  "cat /var/lib/dpkg/status.d/* | egrep 'Package|Version'"]
            bboxcommand = ["sh", "-c", "busybox | grep 'BusyBox v' | awk '{print $1,$2}'"]
            oneline,_ = run_command_in_image(image, bboxcommand)
            first_pass = oneline.decode().split()
            result = [ {"provider": os, "package": first_pass[0], "version": first_pass[1]}]
        case "fedora":
            command =  ["rpm", "-qa"]
        case "ubuntu":
            command = ["dpkg-query", "-W"]
    if not command:
        return [{"provider": os, "package": None, "version": None}]

    (output, _) = run_command_in_image(image, command)
    (pip_output, _) = run_command_in_image(image, ["python3", "-m", "pip", "list", "--format", "freeze"])
    os_result = parse_packages(os, output.decode())
    result = result + os_result
    if not pip_output:
        pip_result = parse_packages("pip", pip_output.decode())
        result += pip_result
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan docker images.')
    parser.add_argument('--images', nargs=argparse.REMAINDER, required=True)
    args = parser.parse_args()

    result = dict()
    for image in args.images: 
        pkg_list = get_packages(image)
        inspect_data = get_inspect_data(image)
        result[image] = { "pkg_list": pkg_list }
        result[image]["inspect_data"] = inspect_data

    print(json.dumps(result))
