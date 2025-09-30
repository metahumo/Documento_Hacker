
---
# PoC_Tutorial: proxychains (PoC_tutorial_proxychains.md)

**Resumen**  
Este documento muestra un _Proof-of-Concept_ y tutorial práctico para usar **proxychains** (principalmente proxychains-ng / proxychains4) en entornos Linux. Cubre instalación, configuración, ejemplos de uso con Tor y SOCKS proxies, varios scripts de ejemplo con sus salidas simuladas, y buenas prácticas y mitigaciones.

> **Aviso legal y ético**: las técnicas descritas sirven para pruebas autorizadas de seguridad, anonimato y troubleshooting. No deben usarse para actividades ilegales o no autorizadas. Obtén siempre permiso antes de probar en sistemas que no sean tuyos.

---

## Índice

1. Introducción rápida
    
2. ¿Qué hace proxychains y limitaciones
    
3. Instalación
    
4. Archivo de configuración `/etc/proxychains.conf` — explicación línea a línea
    
5. Modos de operación: `strict_chain`, `dynamic_chain`, `random_chain`
    
6. PoC 1 — Forzar `curl` a través de Tor (Socks5)
    
7. PoC 2 — Encadenar múltiples proxies (SOCKS + HTTP)
    
8. PoC 3 — Usar `ssh -D` como proxy local y ejecutar `proxychains4 wget`
    
9. Ejemplos de scripts automatizados (con "Qué se ha añadido" y "Explicación")
    
10. Comprobación y debugging (salidas, `-v`, problemas comunes)
    
11. Defensa y mitigaciones (cómo detectar/evitar proxied exfiltration)
    

---

## 1. Introducción rápida

> `proxychains` es un «preloader» que intercede en las llamadas de red de programas enlazados dinámicamente y redirige las conexiones TCP a través de uno o varios proxies (SOCKS4/5, HTTP CONNECT). La versión moderna suele llamarse **proxychains-ng** y el ejecutable normalmente es `proxychains4`.

**Limitaciones importantes**:

- Solo redirige **TCP**. No soporta UDP/ICMP. Muchas herramientas (p. ej. `nmap` con ping) pueden no funcionar correctamente.
    
- Necesita que el binario sea dinámicamente enlazado (no funcionará con algunos binarios estáticos o setuid).
    

## 2. ¿Qué hace proxychains y limitaciones (resumen técnico)

- Hookea llamadas de la libc (LD_PRELOAD) y fuerza que las conexiones salientes pasen por proxies configurados.
    
- Ofrece varias políticas para elegir proxies y encadenarlos.
    

(Ver referencias en GitHub y manpages para detalles de implementación.)

---

## 3. Instalación

En Debian/Ubuntu/Kali:

```bash
sudo apt update
sudo apt install proxychains4
```

En macOS (Homebrew):

```bash
brew install proxychains-ng
```

Desde fuente (proxychains-ng GitHub):

```bash
git clone https://github.com/rofl0r/proxychains-ng.git
cd proxychains-ng
sudo ./configure
make
sudo make install
```

---

## 4. Archivo de configuración `/etc/proxychains.conf`

Ejemplo mínimo comentado (fragmento):

```ini
# /etc/proxychains.conf
strict_chain
#proxy_dns
#timeout 2000
[ProxyList]
# formato: type host port [user pass]
# socks5 127.0.0.1 9050
# http  192.0.2.10 8080
```

Explicación de las opciones clave:

- `strict_chain` — las conexiones seguirán la cadena en orden y fallan si un proxy cae.
    
- `dynamic_chain` — selecciona dinámicamente proxies de la lista; ignora los que fallen.
    
- `random_chain` — elige proxies al azar para cada conexión.
    
- `proxy_dns` — fuerza la resolución DNS a través del proxy para evitar DNS leaks.
    
- `tcp_read_time_out` / `tcp_connect_time_out` — controlan timeouts.
    

---

## 5. Modos de operación

- **strict_chain**: control total del orden, útil cuando necesitas pasar por un salto intermedio específico.
    
- **dynamic_chain**: más tolerante; continúa con otros proxies si uno falla.
    
- **random_chain**: no determinista, útil para evasión simple pero menos predecible.
    

---

## 6. PoC 1 — Forzar `curl` a través de Tor (Socks5)

**Objetivo:** comprobar el IP público visto por un servicio HTTP cuando usamos Tor.

**Requisitos:** Tor corriendo localmente en `127.0.0.1:9050` (por ejemplo `sudo systemctl start tor` en Debian/Kali).

### Script / comandos

```bash
# 1) configurar /etc/proxychains.conf -> añadir al final:
# socks5  127.0.0.1 9050

# 2) ejecutar:
proxychains4 curl -s https://ipinfo.io/ip
```

### Qué se ha añadido

Se ha añadido un proxy de tipo `socks5` apuntando a Tor en `127.0.0.1:9050`.

### Explicación

`proxychains4` pre-carga la librería que intercepta `connect()` y otras llamadas; cuando `curl` intenta conectarse, la conexión pasa por el socket SOCKS5 de Tor y el servicio `ipinfo.io` verá la IP de salida de la red Tor.

### Salida esperada (ejemplo)

```
198.51.100.23
```

(Esta IP será diferente cada vez; si ves tu IP real, verifica `proxy_dns` y la configuración de Tor.)

---

## 7. PoC 2 — Encadenar múltiples proxies (SOCKS + HTTP)

**Objetivo:** mostrar cómo encadenar proxies para crear un salto adicional.

### `/etc/proxychains.conf` (fragmento)

```ini
dynamic_chain
proxy_dns
[ProxyList]
# primer salto: socks5 local (Tor)
socks5 127.0.0.1 9050
# segundo salto: HTTP CONNECT remoto
http  203.0.113.7 8080
```

### Comando de PoC

```bash
proxychains4 curl -s https://ipinfo.io/json | jq .ip
```

### Qué se ha añadido

Se ha añadido un proxy HTTP remoto tras el proxy SOCKS local para forzar 2 saltos.

### Explicación

Con `dynamic_chain`, si el primer proxy (Tor) está activo y acepta la conexión, el tráfico se enviará y luego se encadenará al proxy HTTP configurado (si la herramienta y el proxy remoto permiten el encadenamiento). Algunos proxies no permiten encadenamiento o requieren configuración específica.

---

## 8. PoC 3 — Usar `ssh -D` como proxy local y ejecutar `proxychains4 wget`

**Objetivo:** crear un SOCKS proxy local usando SSH y luego forzar una descarga a través de él.

### Comandos

```bash
# en equipo atacante (cliente)
ssh -f -N -D 1080 user@jump.example.org
# añadir a /etc/proxychains.conf
# socks5 127.0.0.1 1080

proxychains4 wget -qO- http://example.com | head -n 20
```

### Qué se ha añadido

Se añadió un túnel dinámico SSH (`-D`) actuando como SOCKS5 local.

### Explicación

`ssh -D` abre un proxy SOCKS dinámico. `proxychains4` redirige las conexiones de `wget` a través de ese SOCKS local, lo cual es muy útil para pivoting o para salir por una máquina intermedia.

### Salida esperada (fragmento HTML)

```
<!doctype html>
<html>
<head>...
```

---

## 9. Ejemplos de scripts automatizados

A continuación tres scripts con la estructura solicitada (Código — Qué se ha añadido — Explicación — Salida esperada).

### Script A — `test_tor.sh`

```bash
#!/bin/bash
# test_tor.sh — prueba rápida de proxychains + tor
CONF=/etc/proxychains.conf
# aseguramos entry
grep -q "socks5 127.0.0.1 9050" $CONF || echo "socks5 127.0.0.1 9050" | sudo tee -a $CONF
proxychains4 -q curl -s https://ipinfo.io/ip
```

**Qué se ha añadido**

- Añade la línea `socks5 127.0.0.1 9050` al final de `/etc/proxychains.conf` si no existe.
    

**Explicación**

- Automatiza la verificación del IP público a través de Tor.
    

**Salida esperada**

```
198.51.100.23
```

---

### Script B — `chain_check.sh` (comprobación de cadena dinámica)

```bash
#!/bin/bash
# chain_check.sh
CONF=/etc/proxychains.conf
cat > /tmp/proxy_test.conf <<EOF
dynamic_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 9050
http 203.0.113.7 8080
EOF
proxychains4 -f /tmp/proxy_test.conf -v curl -I https://example.com
```

**Qué se ha añadido**

- Crea y usa un archivo de configuración temporal con `dynamic_chain` y dos proxies.
    

**Explicación**

- Permite ver en modo verbose (`-v`) cómo proxychains intenta conectar a cada salto y detectar fallos.
    

**Salida esperada (fragmento)**

```
|-- ProxyChains-4.14 (http://proxychains.sf.net)
|-- Resolving hostname example.com
|-- Proxy 127.0.0.1:9050 (SOCKS5) connected.
HTTP/1.1 200 OK
...
```

---

### Script C — `ssh_socks_test.sh`

```bash
#!/bin/bash
ssh -f -N -D 1080 user@jump.example.org
proxychains4 -q curl -s https://ipinfo.io/ip
```

**Qué se ha añadido**

- Crea un túnel SSH dinámico y luego consulta IP a través de ese SOCKS.
    

**Explicación**

- Muestra cómo usar `ssh -D` para crear proxies temporales para pruebas o pivoting.
    

**Salida esperada**

```
203.0.113.45
```

---

## 10. Comprobación y debugging

- Usa `proxychains4 -v` para ver trazas de conexión.
    
- Verifica `proxy_dns` si observas filtrado DNS.
    
- Ten en cuenta que aplicaciones que usan sus propias librerías de red (Go estático, binarios estáticos, o algunas apps sandboxed) pueden no funcionar con LD_PRELOAD.
    
- `strace -e trace=network -f proxychains4 <comando>` ayuda a ver syscalls de red.
    

---

## 11. Defensa y mitigaciones

- Monitoriza procesos que ejecutan `LD_PRELOAD` inusual o que tengan bibliotecas pre-cargadas.
    
- Inspecciona conexiones salientes y correlación de destinos con perfiles de usuarios.
    
- Bloquea o autentica proxies salientes a nivel de red (firewall e IP allowlists) y TLS inspection si procede.
    

---
