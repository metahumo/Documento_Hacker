
---

# PoC Tutorial — Cadena de proxys con proxychains, Docker y SSH 

Complementar esta lectura con [Automatización de Proxy con scripts en bash](Automatización%20de%20Proxy%20con%20scripts%20en%20bash.md)

## Objetivo

Montar una cadena de 3 proxys para pruebas controladas de pentesting:

- 2 proxys dentro de contenedores Docker (SOCKS vía SSH)
    
- 1 proxy en la VM Debian/Ubuntu (SOCKS vía SSH)
    
- (Opcional) Tor como cuarta capa para navegación anónima
    

Todo el flujo se realiza paso a paso desde la VM hasta la validación en la máquina atacante (Parrot).

---

## Requisitos previos

- **Host atacante:** Parrot OS.
    
- **Máquina virtual (VM) en VMware:** Debian o Ubuntu.
    
- **Docker** instalado y funcionando en la VM.
    
- Conexión de red entre Parrot ↔ VM (bridged o NAT).
    
- Usuario con privilegios sudo en la VM (ej.: labuser).
    
- En Parrot: ssh, proxychains, herramientas de pruebas (curl, nmap, etc.).
    

---

## Paso 1 — Preparar la VM (Debian/Ubuntu)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y openssh-server curl wget sudo net-tools iproute2 ca-certificates gnupg lsb-release
sudo adduser labuser
sudo usermod -aG sudo labuser
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh
```

> Anotar la IP de la VM (`ip a`) para usarla desde Parrot.

---

## Paso 2 — Instalar Docker en la VM

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker labuser
docker --version
docker run --rm hello-world
```

---

## Paso 3 — Dockerfile para contenedor SOCKS/SSH ligero

```Dockerfile
FROM alpine:latest
RUN apk add --no-cache openssh sudo bash
RUN mkdir /var/run/sshd
RUN adduser -D -u 1000 pentester \
 && echo "pentester:pentester123" | chpasswd \
 && echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-E", "/var/log/sshd.log"]
```

Construir imagen:

```bash
docker build -t socks-ssh:latest .
```

---

## Paso 4 — Ejecutar 2 contenedores

```bash
docker run -d --name socks1 -p 2222:22 socks-ssh:latest
docker run -d --name socks2 -p 2223:22 socks-ssh:latest
docker ps
```

> Opcional: red bridge personalizada:

```bash
docker network create --subnet=172.18.0.0/16 proxy_net
docker run -d --name socks1 --network proxy_net --ip 172.18.0.10 -p 2222:22 socks-ssh:latest
docker run -d --name socks2 --network proxy_net --ip 172.18.0.11 -p 2223:22 socks-ssh:latest
```

---

## Paso 5 — Abrir túneles SSH-SOCKS

### Desde Parrot → VM

```bash
ssh -f -N -D 1080 labuser@IP_VM
```

### Desde VM → contenedores

```bash
ssh -f -N -D 1081 pentester@localhost -p 2222
ssh -f -N -D 1082 pentester@localhost -p 2223
```

> Alternativa: desde Parrot directamente usando puertos mapeados.

---

## Paso 6 — Configurar proxychains (Parrot)

```ini
proxy_dns
strict_chain
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
```

---

## Paso 7 — Validación

```bash
proxychains curl -s https://ifconfig.me
proxychains curl -s https://ipinfo.io/ip
proxychains dig +short myip.opendns.com @resolver1.opendns.com
proxychains nmap -sT -Pn -p 80 example.com
```

---

## Paso 8 — Tor opcional

```bash
sudo apt update && sudo apt install -y tor torsocks
sudo systemctl enable tor
sudo systemctl start tor
```

Agregar al final de proxychains.conf:

```
socks5 127.0.0.1 9050
```

> Solo para navegación web.

---

## Paso 9 — Secuencia de uso

### start_tunnels.sh

```bash
#!/bin/bash
# Abrir túneles SSH-SOCKS
ssh -f -N -D 1080 labuser@IP_VM
ssh -f -N -D 1081 pentester@localhost -p 2222
ssh -f -N -D 1082 pentester@localhost -p 2223
```

---
