#!/bin/bash

function ctrl_c(){
  echo -e "\n\n[!] Saliendo...\n"
  tput cnorm; exit 1
}

# Ctrl+C
trap ctrl_c INT

tput civis

for port in $(seq 1 65536); do
  timeout 1 bash -c "echo '' > /dev/tcp/<IP_Objetivo>/$port" 2>/dev/null && echo "[+] Puerto abierto: $port" &
done; wait
tput cnorm
