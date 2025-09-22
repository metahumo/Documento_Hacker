
---

# Configurar proxy a través de Docker

Complementar esta lectura con [Proxychains](./proxychains_PoC_tutorial.md)
## Resumen

Este PoC documenta cómo montar una **cadena de proxys** para laboratorio de pentesting usando:

- Un host Debian/VM (sin GUI) que corre **Docker** — aquí levantamos los contenedores proxy (SOCKS via SSH).
    
- Como máquina atacante **Parrot** (VMware) — desde donde abrimos túneles `ssh -D` y usamos `proxychains`.
    

La idea general: dos contenedores Docker que ejecutan `sshd` (socks-ssh), un host VM que los contiene, y la máquina atacante que encadena los saltos mediante túneles SSH dinámicos (SOCKS5).

---

## Arquitectura y componentes

- **VM Debian (host Docker)**
    
    - Construye una imagen Docker `socks-ssh:latest` (Alpine con `sshd`).
        
    - Levanta 2 contenedores: `socks1` y `socks2`, puertos mapeados `2222` y `2223`.
        
    - Opcional: red Docker `proxy_net` con subred `172.18.0.0/16` y IPs fijas `172.18.0.10/11`.
        
- **Parrot (atacante)**
    
    - Genera clave SSH `ed25519`.
        
    - Copia clave pública a VM/contendores para acceso sin contraseña.
        
    - Abre 3 túneles dinámicos (`ssh -D`) apuntando a VM y a los puertos del contenedor.
        
    - Configura `proxychains` apuntando a los sockets locales (1080, 1081, 1082).
        

---

## Archivos incluidos en este PoC (en el repo `~/Proxy` de tu VM)

- `Dockerfile` — imagen mínima basada en Alpine con `sshd` configurado.
    
- `docker-compose.yml` — (más abajo) levanta `socks1` y `socks2` y la red `proxy_net`.
    
- `start_tunnels.sh` — script para ejecutar desde Parrot que abre los túneles `ssh -D` en background usando tu llave SSH.
    
- `proxy_PoC_tutorial.md` — este documento.
    

---

## Dockerfile recomendado

Este `Dockerfile` genera una imagen `socks-ssh:latest` ligera con `sshd`, host keys y configuración necesaria para permitir `ssh -D` (AllowTcpForwarding).

```Dockerfile
FROM alpine:latest

# instalar openssh y bash
RUN apk add --no-cache openssh sudo bash

# crear directorios necesarios
RUN mkdir -p /var/run/sshd /var/log

# generar host keys
RUN ssh-keygen -A

# crear usuario 'proxy_02' con password (solo laboratorio)
RUN adduser -D -u 1000 proxy_02 \
 && echo "proxy_02:1234" | chpasswd \
 && echo "proxy_02 ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# asegurar opciones útiles para tunneling
RUN sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true \
 && sed -i 's/AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config || echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config \
 && sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-E", "/var/log/sshd.log"]
```

> Nota: en producción **no** dejes contraseñas en texto. Usa `authorized_keys` y elimina contraseñas.

---

## docker-compose.yml

Este `docker-compose.yml` levanta la red `proxy_net` y los dos contenedores con IPs fijas y puertos mapeados.

```yaml
version: '3.8'
services:
  socks1:
    image: socks-ssh:latest
    container_name: socks1
    networks:
      proxy_net:
        ipv4_address: 172.18.0.10
    ports:
      - "2222:22"
    restart: unless-stopped

  socks2:
    image: socks-ssh:latest
    container_name: socks2
    networks:
      proxy_net:
        ipv4_address: 172.18.0.11
    ports:
      - "2223:22"
    restart: unless-stopped

networks:
  proxy_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.18.0.0/16
```

**Uso**:

- En la VM host (donde está Docker): `docker-compose up -d` para levantar ambos contenedores.
    
- `docker-compose down` para parar y eliminar los contenedores y la red creada por compose.
    

---

## Generar claves SSH en Parrot — explicación detallada del `-t ed25519`

### ¿Por qué `ed25519`?

`ed25519` es un tipo de clave moderno y eficiente (curva Edwards25519). Ventajas:

- claves y firmas pequeñas
    
- alto rendimiento (rápido en firmar/validar)
    
- seguridad moderna sin necesidad de claves RSA enormes
    

### Comando recomendado

En **Parrot**, genera la pareja de claves con:

```bash
ssh-keygen -t ed25519 -C "parrot_lab"
```

Parámetros:

- `-t ed25519` → tipo de clave (Ed25519)
    
- `-C "parrot_lab"` → comentario que ayuda a identificar la clave
    

Te pedirá un path (acepta `~/.ssh/id_ed25519`) y **passphrase**. Si vas a automatizar túneles puedes dejar la passphrase vacía (presiona Enter) o mejor usar `ssh-agent` y añadir la clave al agente para no exponerla.

### Ver fingerprint

```bash
ssh-keygen -lf ~/.ssh/id_ed25519.pub
```

### Copiar la clave al VM / contenedores

Si el contenedor escucha en `IP_VM:2222`:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2222 proxy_02@IP_VM
```

Si `ssh-copy-id` no está disponible:

```bash
cat ~/.ssh/id_ed25519.pub | ssh -p 2222 proxy_02@IP_VM 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
```

---

## Scripts auxiliares para Docker y túneles

### `start_docker.sh`

```bash
#!/usr/bin/env bash
# start_docker.sh
# Reset total de Docker y levantar PoC con imágenes locales

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

echo "=== Creando red del PoC ==="
docker network create --subnet=${SUBNET} ${NET_NAME} 2>/dev/null || echo "Red ${NET_NAME} ya existe"

echo "=== Levantando contenedores con docker compose ==="
docker compose -f ${COMPOSE_FILE} up -d

echo "=== Estado final ==="
docker ps
docker network ls | grep ${NET_NAME}
```

---

###  `stop_docker.sh`

```bash
!/usr/bin/env bash
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

---

## start_tunnels.sh (script para ejecutar desde Parrot)

- Este script abre 3 túneles dinámicos (`ssh -D`) en background usando tu clave por defecto (`~/.ssh/id_ed25519`).
    
- Requiere que la clave pública ya esté autorizada en `labuser@IP_VM` y en `proxy_02@IP_VM` (puerto 2222/2223).
    

```bash
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
```

**Permisos:** `chmod +x start_tunnels.sh`  
**Uso:** `./start_tunnels.sh <IP_VM>` (ej.: `./start_tunnels.sh 192.168.1.50`)

---

## stop_tunnels.sh (script para cerrar túneles y limpiar)

- Este script cierra los procesos SSH que ocupan los puertos 1080-1082 y opcionalmente detiene los contenedores Docker.
    

```bash
#!/bin/bash
# stop_tunnels.sh
# Cierra los túneles SOCKS creados por start_tunnels.sh

for port in 1080 1081 1082; do
    pid=$(lsof -ti tcp:$port)
    if [ -n "$pid" ]; then
        echo "Cerrando túnel SOCKS en puerto $port (PID $pid)"
        kill $pid
    fi
done

# Opcional: parar contenedores en VM (desde Parrot vía SSH o directamente en la VM)
# ssh labuser@<IP_VM> "docker-compose -f ~/Proxy/docker-compose.yml down"
```

**Permisos:** `chmod +x stop_tunnels.sh`  
**Uso:** `./stop_tunnels.sh`

---

## Secuencia de uso completa — Start → Use → Stop

### A) Preparar (solo una vez)

1. En **VM con Docker**:
    

```bash
# levantar contenedores y red
./start_docker.sh
```

2. En **Parrot**:
    

```bash
# generar clave SSH para túneles (solo la primera vez)
ssh-keygen -t ed25519 -C "parrot_lab"

# copiar la clave pública a VM y contenedores
ssh-copy-id labuser@IP_VM
ssh-copy-id -p 2222 proxy_02@IP_VM
ssh-copy-id -p 2223 proxy_02@IP_VM
```

---

### B) Start / Uso (cada sesión)

1. Abrir túneles SSH-SOCKS:
    

```bash
./start_tunnels.sh <IP_VM>
```

2. Configurar `proxychains.conf` (ej.: `~/.proxychains/proxychains.conf`):
    

```ini
proxy_dns
strict_chain

[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
```

3. Probar IP final y herramientas:
    

```bash
proxychains curl https://ifconfig.me
proxychains nmap -sT -Pn -p 80 example.com
```

---

### C) Stop / Cleanup

1. Cerrar túneles SSH-SOCKS:
    

```bash
./stop_tunnels.sh
```

2. Parar contenedores y eliminar red si no se van a reutilizar:
    

```bash
./stop_docker.sh
```



---

## Secuencia de uso (Start → Use → Stop) — paso a paso

### A) Preparar (solo una vez)

1. En **VM (Debian con Docker)**:
    
    - Colocar `Dockerfile` en `~/Proxy` y `docker-compose.yml` en el mismo directorio.
        
    - Construir imagen:
        
    
    ```bash
    docker build -t socks-ssh:latest ~/Proxy
    ```
    
    - Levantar contenedores con compose:
        
    
    ```bash
    docker-compose -f ~/Proxy/docker-compose.yml up -d
    ```
    
2. En **Parrot**:
    
    - Generar clave: `ssh-keygen -t ed25519 -C "parrot_lab"` (aceptar defaults, sin passphrase si quieres automatizar túneles).
        
    - Copiar pública al VM y a los contenedores (puertos 22/2222/2223):
        
    
    ```bash
    ssh-copy-id labuser@IP_VM
    ssh-copy-id -p 2222 proxy_02@IP_VM
    ssh-copy-id -p 2223 proxy_02@IP_VM
    ```
    

---

### B) Start (cada vez que quieras usar la cadena)

1. Desde **Parrot**, abrir túneles:
    

```bash
./start_tunnels.sh <IP_VM>
```

Esto crea los 3 sockets locales: 1080 (VM), 1081 (Cont1), 1082 (Cont2).

2. Configurar `proxychains.conf` (ej.: `~/.proxychains/proxychains.conf`):
    

```ini
proxy_dns
strict_chain

[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
```

3. Probar IP final:
    

```bash
proxychains curl https://ifconfig.me
```

4. Ejecutar herramientas encadenadas con `proxychains` (nmap con `-sT`, curl, navegadores configurados para SOCKS5, etc.)
    

---

### C) Stop / Cleanup (cerrar túneles y contenedores)

1. Cerrar túneles SSH (Parrot):
    

```bash
./stop_tunnels.sh
```

2. Parar contenedores en la VM (opcional):
    

```bash
docker-compose -f ~/Proxy/docker-compose.yml down
```

3. (Opcional) eliminar red creada por docker-compose:
    

```bash
docker network ls  # localizar la red
docker network rm <network_name>
```


---

## Seguridad y buenas prácticas

- Usa `authorized_keys` (clave pública) en vez de contraseñas para los contenedores/VM.
    
- No dejes contraseñas por defecto en imágenes públicas.
    
- Aísla el laboratorio en una red privada.
    
- No uses Tor para escaneos intensivos; Tor es para navegación anónima.
    

---

