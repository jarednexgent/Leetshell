# Leetshell

[![leetshell-2.png](https://i.postimg.cc/NjmkWQg0/leetshell-2.png)](https://postimg.cc/sMfWWdGF)

#### Polymorphic, Position-Independent Reverse-Shell Generator

Leetshell creates unique, position-independent shellcode for 64-bit Windows targets. It can produce both CMD and PowerShell reverse shells, packaging them as C-style arrays or raw binaries.

---

### Features

- Random XOR key ensures a fresh, polymorphic payload on each run
- Supports CMD and PowerShell reverse-shell shellcode
- Outputs as a C-array or writes directly to a raw .bin file

---

### Usage

```
./leetshell.sh <ip> <port> [cmd|powershell] [--raw]
```

[![leetshell-demo-2.gif](https://i.postimg.cc/MKmt3Wtm/leetshell-demo-2.gif)](https://postimg.cc/56jw6WhX)

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



