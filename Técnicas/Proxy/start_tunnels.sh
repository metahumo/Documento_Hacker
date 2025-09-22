#!/usr/bin/env bash
# start_tunnels.sh
# Uso: ./start_tunnels.sh <IP_VM> [ssh_user_vm]
# Este script abre túneles SOCKS a la VM y a contenedores Docker
# Limpiando host keys viejas y cerrando túneles previos

IP_VM="$1"
SSH_USER_VM="${2:-proxy_01}"  # Usuario por defecto

SOCK_VM=1080
SOCK_C1=1081
SOCK_C2=1082

# Verificar parámetro
if [ -z "$IP_VM" ]; then
  echo "Uso: $0 <IP_VM> [ssh_user_vm]"
  exit 1
fi

PORTS=($SOCK_VM $SOCK_C1 $SOCK_C2)

echo "=== Limpieza de claves SSH antiguas ==="
ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[$IP_VM]:2222" 2>/dev/null || true
ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[$IP_VM]:2223" 2>/dev/null || true

echo "=== Cerrando túneles previos si existen ==="
for port in "${PORTS[@]}"; do
  pid=$(lsof -ti tcp:$port)
  if [ -n "$pid" ]; then
    echo "Cerrando túnel previo en puerto $port (PID $pid)"
    kill $pid
    sleep 0.3
  fi
done

# Función para abrir túnel SOCKS
open_socks() {
  local port="$1"
  local user="$2"
  local host="$3"
  local ssh_port="$4"

  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/home/$USER/.ssh/known_hosts \
      -f -N -D "$port" "$user@$host" -p "$ssh_port" 2>/dev/null

  if [ $? -eq 0 ]; then
    pid=$(lsof -ti tcp:$port)
    echo "Túnel abierto: localhost:$port -> $host:$ssh_port (PID $pid)"
  else
    echo "ERROR: No se pudo abrir túnel en localhost:$port"
  fi
}

echo "=== Abriendo túnel a la VM ==="
open_socks $SOCK_VM $SSH_USER_VM $IP_VM 22

echo "=== Abriendo túneles a contenedores Docker ==="
open_socks $SOCK_C1 proxy_02 $IP_VM 2222
open_socks $SOCK_C2 proxy_02 $IP_VM 2223

echo "=== Estado final de los túneles ==="
for port in "${PORTS[@]}"; do
  lsof -i tcp:$port | grep LISTEN || echo "Puerto $port cerrado"
done

exit 0
