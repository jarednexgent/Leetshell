# Leetshell

[![leetshell-logo.png](https://i.postimg.cc/VLhLqv3K/leetshell-logo.png)](https://postimg.cc/F7j4mrFS)

Leetshell is a polymorphic reverse-shell payload generator for 64-bit Windows targets.

## Features

- Generates x64 CMD or PowerShell reverse-TCP shellcode
- Produces unique builds via per-run XOR keys and randomized API hash seeds
- Emits payloads as a C array, EXE, DLL, or raw binary
- Works from common Linux toolchains with a simple script + Makefile

## Usage

Run `leetshell.sh` with your listener IP and port. You can optionally specify the shell type, payload format, and output file path.

```
██╗     ███████╗███████╗████████╗ ███████╗██╗  ██╗███████╗██╗     ██╗      
██║     ██╔════╝██╔════╝╚══██╔══╝ ██╔════╝██║  ██║██╔════╝██║     ██║ 
██║     █████╗  █████╗     ██║    ███████╗███████║█████╗  ██║     ██║      
██║     ██╔══╝  ██╔══╝     ██║    ╚════██║██╔══██║██╔══╝  ██║     ██║ 
███████╗███████╗███████╗   ██║    ███████║██║  ██║███████╗███████╗███████╗ 
╚══════╝╚══════╝╚══════╝   ╚═╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
 Copyright © 2025 jarednexgent (https://github.com/jarednexgent)  

Usage: 
   ./leetshell.sh [-h] -i IP -p PORT [-t TYPE] [-f FORMAT] [-o OUTPUT]

Options:
  -i, --ip        IP address
  -p, --port      listening port
  -t, --type      shell type {cmd, powershell}
  -f, --format    payload format {c, exe, dll, raw}
  -o, --output    output file path
  -h, --help      show this help message
```

By default, Leetshell selects the `cmd` shell type and outputs the payload in `c` byte array format to stdout.

If `exe`, `dll`, or `raw` payload formats are selected without specifying an output path, the payload is saved as `output.<ext>`, where `<ext>` matches the selected format.

## System Requirements

- Linux (Kali, Parrot, Ubuntu, etc.)
- Core utilities: `bash`, `make`, `sed`, `hexdump`, `objcopy`, `printf`
- MinGW-w64: `x86_64-w64-mingw32-gcc`, `x86_64-w64-mingw32-ld`
- `nasm` (`-f win64`)



