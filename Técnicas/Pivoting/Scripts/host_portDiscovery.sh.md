
#!/bin/bash

for i in $(seq 1 254); do
  for port in 12 22 53 80 443 445 8080; do
    timeout 1 bash -c "echo '' > /dev/tcp/10.10.0.$i/$port" &>/dev/null && echo "[+] Host 10.10.0.$i -PORT $port - ABIERTO" &
  done
done; wait