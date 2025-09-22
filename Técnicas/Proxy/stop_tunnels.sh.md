
---

```bash
#!/usr/bin/env bash
# stop_tunnels.sh
# Cerrar túneles SOCKS

PORTS=(1080 1081 1082)

echo "=== Cerrando túneles SOCKS ==="
for port in "${PORTS[@]}"; do
    pid=$(lsof -ti tcp:$port)
    if [ -n "$pid" ]; then
        echo "Cerrando túnel en puerto $port (PID $pid)"
        kill $pid
    else
        echo "No hay túnel activo en puerto $port"
    fi
done

echo "=== Verificación final ==="
for port in "${PORTS[@]}"; do
    lsof -i tcp:$port | grep LISTEN || echo "Puerto $port cerrado"
done
```