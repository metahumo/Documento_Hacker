
```bash
#!/usr/bin/env bash
# start_docker.sh
# Reset total de Docker y levantar Proxy con imágenes locales

NET_NAME="proxy_net"
SUBNET="172.18.0.0/16"
COMPOSE_FILE="/home/proxy_01/Proxy/docker-compose.yml"

echo "=== Limpieza completa de Docker ==="
docker rm -f $(docker ps -a -q) 2>/dev/null || true
docker rmi -f $(docker images -q) 2>/dev/null || true
docker network rm $(docker network ls -q | grep -vE 'bridge|host|none') 2>/dev/null || true
docker volume rm $(docker volume ls -q) 2>/dev/null || true

echo "=== Construyendo imagen local ==="
docker build -t socks-ssh:latest /home/proxy_01/Proxy || { echo "Error construyendo imagen"; exit 1; }

echo "=== Creando red del Proxy ==="
docker network create --subnet=${SUBNET} ${NET_NAME} 2>/dev/null || echo "Red ${NET_NAME} ya existe"

echo "=== Levantando contenedores con docker compose ==="
docker compose -f ${COMPOSE_FILE} up -d

echo "=== Estado final ==="
docker ps
docker network ls | grep ${NET_NAME}
```