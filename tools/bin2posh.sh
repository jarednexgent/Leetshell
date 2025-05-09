#!/bin/bash

# === validate input ===
if [ $# -ne 1 ]; then
  echo "[!] Usage: $0 <file.bin>"
  exit 1
fi

input="$1"
if [ ! -f "$input" ]; then
  echo "[!] File not found: $input"
  exit 1
fi

# === generate Microshell-style PS array ===
echo "[Byte[]] \$buf = "
hexdump -v -e '16/1 "0x%02x," "\n"' "$input" | tr -d '\n' | sed 's/,$//'
echo ""

