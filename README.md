# Leetshell

[![leetshell-logo.png](https://i.postimg.cc/VLhLqv3K/leetshell-logo.png)](https://postimg.cc/F7j4mrFS)

#### Polymorphic, Position-Independent Windows Shellcode Generator

Leetshell creates unique, position-independent shellcode for 64-bit Windows targets. It can produce both CMD and PowerShell reverse shells, packaging them as C-style arrays or raw binaries.

---

### Features

- Randomized multi-byte XOR encryption ensures a fresh, polymorphic payload on each run
- Supports CMD and PowerShell reverse-shell shellcode
- Outputs as a C-array or writes directly to a raw .bin file

---

### Usage

```
./Leetshell.sh <ip> <port> [cmd|powershell] [--raw]
```

[![Leetshell.gif](https://i.postimg.cc/LszYJh8y/Leetshell.gif)](https://postimg.cc/XZY7hjFF)

---

### System Requirements

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

