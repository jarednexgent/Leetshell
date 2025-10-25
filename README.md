# Leetshell

[![leetshell-logo.png](https://i.postimg.cc/VLhLqv3K/leetshell-logo.png)](https://postimg.cc/F7j4mrFS)

Leetshell creates polymorphic reverse-shell payloads for 64-bit Windows targets.

## Features

- Generates x64 CMD or PowerShell reverse-TCP shellcode
- Produces unique builds via per-run XOR keys and randomized API-hash seeds
- Emits payloads as a C array, EXE, DLL, or raw binary
- Works from common Linux toolchains with a simple script + Makefile

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

## Usage

Run `Leetshell.sh` with your listener IP and port. You can optionally specify the shell type, payload format, and output filename.

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
  -o, --output    output file path (optional)
  -h, --help      show this help message
```

By default, Leetshell generates a reverse shell for `cmd.exe` and outputs the shellcode as a C-style byte array to stdout.

If you select the `exe`, `dll`, or `raw` formats and don’t specify an output path, the payload will be saved as:
- `output.exe`
- `output.dll`
- `output.bin`

