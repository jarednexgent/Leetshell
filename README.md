# Leetshell

[![leetshell-logo.png](https://i.postimg.cc/VLhLqv3K/leetshell-logo.png)](https://postimg.cc/F7j4mrFS)

Leetshell creates polymorphic reverse-shell payloads for 64-bit Windows targets.

## Features

- Generates x64 CMD or PowerShell reverse-TCP payloads
- Produces unique builds via per-run XOR keys and randomized API-hash seeds
- Emits payloads as a C array, EXE, DLL, or raw shellcode
- Works from common Linux toolchains with a simple script + Makefile

## Usage

Run `Leetshell.sh` with your listener IP and port; optionally specify the shell type, payload format, and output path.

```
██╗     ███████╗███████╗████████╗ ███████╗██╗  ██╗███████╗██╗     ██╗      
██║     ██╔════╝██╔════╝╚══██╔══╝ ██╔════╝██║  ██║██╔════╝██║     ██║ 
██║     █████╗  █████╗     ██║    ███████╗███████║█████╗  ██║     ██║      
██║     ██╔══╝  ██╔══╝     ██║    ╚════██║██╔══██║██╔══╝  ██║     ██║ 
███████╗███████╗███████╗   ██║    ███████║██║  ██║███████╗███████╗███████╗ 
╚══════╝╚══════╝╚══════╝   ╚═╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
 Copyright © 2025 jarednexgent (https://github.com/jarednexgent)  

Usage: 
   ./Leetshell.sh [-h] -i IP -p PORT [-t TYPE] [-f FORMAT] [-o OUTPUT]

Options:
  -i, --ip        IP address
  -p, --port      listening port
  -t, --type      shell type {cmd, powershell}
  -f, --format    payload format {c, exe, dll, raw}
  -o, --output    output path
  -h, --help      show this help message
```

## System Requirements

- Linux-based OS (Parrot OS, Kali, Ubuntu, etc.)
- Tools required:
  - `bash`
  - `make`
  - `sed`
  - `hexdump`
  - `objcopy`
  - `printf`
- Cross-compilation toolchain:
  - `x86_64-w64-mingw32-gcc`
  - `x86_64-w64-mingw32-ld`
- Assembler:
  - `nasm` with `-f win64` format

