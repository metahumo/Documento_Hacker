
---

```bash
#!/usr/bin/env bash
# stop_docker.sh
# Uso: ./stop_docker.sh
# Para contenedores y elimina red/volúmenes de manera segura

NET_NAME="proxy_net"

echo "=== Deteniendo contenedores con docker compose ==="
docker compose -f ~/Proxy/docker-compose.yml down 2>/dev/null || true

echo "=== Deteniendo contenedores restantes ==="
active_containers=$(docker ps -q --filter network=${NET_NAME})
if [ -n "$active_containers" ]; then
    docker stop $active_containers 2>/dev/null
fi

echo "=== Eliminando contenedores, imágenes, redes y volúmenes ==="
docker rm -f $(docker ps -a -q) 2>/dev/null || true
docker rmi -f $(docker images -q) 2>/dev/null || true
docker network rm $(docker network ls -q | grep -vE 'bridge|host|none') 2>/dev/null || true
docker volume rm $(docker volume ls -q) 2>/dev/null || true

echo "=== Stop Docker completado ==="
docker ps -a
docker network ls
docker images
docker volume ls
```