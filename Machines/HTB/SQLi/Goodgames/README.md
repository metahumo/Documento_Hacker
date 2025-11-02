# GoodGames - Hack The Box

![Dificultad](https://img.shields.io/badge/Dificultad-Easy-green)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-SQLi%20%7C%20SSTI-red)

---

## Información de la máquina

- **Nombre:** GoodGames
- **Plataforma:** Hack The Box
- **IP:** 10.10.11.130
- **SO:** Linux
- **Dificultad:** Easy
- **Link HTB:** [GoodGames machine](https://app.hackthebox.com/machines/GoodGames)

---

## Resumen ejecutivo

La explotación de GoodGames se desarrolla en **tres fases principales**:

1. **SQL Injection** → Bypass de autenticación y exfiltración de credenciales
2. **SSTI (Server-Side Template Injection)** → Explotación de Jinja2 para RCE
3. **Docker Escape** → Escalada de privilegios desde el contenedor al host

---

## Contenido del directorio

```
Goodgames/
├── README.md                    # Este archivo
├── GoodGames.md                 # Guía completa paso a paso
├── Escape Docker.md             # Documentación sobre escape de contenedores
├── Script/
│   └── (scripts de explotación si los hay)
└── Imágenes/
    └── web_*.png               # Capturas del proceso
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **SQL Injection**
- **Ubicación:** Panel de login
- **Técnica:** Bypass de autenticación mediante inyección SQL
- **Impacto:** Acceso a panel de administración y exfiltración de hashes

### 2. **SSTI (Server-Side Template Injection)**
- **Motor de plantillas:** Jinja2 (Flask)
- **Payload:** `render_template_string` vulnerable
- **Resultado:** RCE (Remote Code Execution)

### 3. **Docker Privilege Escalation**
- **Método:** Montaje del sistema de archivos del host en el contenedor
- **Técnica:** Modificación de permisos desde el contenedor con privilegios
- **Shell obtenida:** Usuario `root` en el host

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos y servicios
- **BurpSuite** - Interceptación y análisis de peticiones HTTP (SQLi)
- **Hashcat** - Cracking de contraseñas
- **PayloadsAllTheThings** - Repositorio de payloads SSTI

---

## 🔗 Referencias y documentación relacionada

- [SQL Injection](../../../../OWASP%20TOP%2010/SQLi/)
- [SSTI (Server-Side Template Injection)](../../../../OWASP%20TOP%2010/SSTI/)
- [Docker Escape](./Escape%20Docker.md)
- [Escalada de privilegios Linux](../../../../Técnicas/Escalada%20de%20privilegios/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
