# Invent

Invent is a dead simple docker image scanner. It will try to scan one or more docker image that it can reach with docker pull and output information about installed packages, operating system and docker inspect information.

## Usage
```
  ./scanner.py --images debian:latest alpine:latest | jq .
```

The above command will download latest debian and alpine images from docker hub and scan them, and output the information in json format.

## Requirements
The scanner needs python 3.10 and docker installed.
