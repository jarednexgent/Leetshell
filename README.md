# Leetshell

[![leetshell-logo.png](https://i.postimg.cc/VLhLqv3K/leetshell-logo.png)](https://postimg.cc/F7j4mrFS)

Leetshell creates unique, position-independent shellcode for 64-bit Windows targets. It can produce both CMD and PowerShell reverse shells, packaging them as C-style arrays or raw binaries.

## Features

- Randomized multi-byte XOR encryption ensures a fresh, polymorphic payload on each run
- Supports CMD and PowerShell reverse-shell shellcode
- Outputs as a C-array or writes directly to a raw `.bin` file

## Usage

Run the script with a listener IP and port. Optionally specify `cmd` or `powershell` as the reverse shell type (defaults to `cmd`). Add `--raw` to output a raw binary instead of a C-style array.

```
./Leetshell.sh <ip> <port> [cmd|powershell] [--raw]
```

[![leetshell-demo.gif](https://i.postimg.cc/5jdsFqYH/leetshell-demo.gif)](https://postimg.cc/p5CfwjBx)

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

