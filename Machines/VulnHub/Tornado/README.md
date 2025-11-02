# Tornado - VulnHub

![Dificultad](https://img.shields.io/badge/Dificultad-Medium-yellow)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-SQL%20Truncation%20%7C%20LFI-red)

---

## Información de la máquina

- **Nombre:** Tornado (IA: Tornado)
- **Plataforma:** VulnHub
- **SO:** Linux
- **Dificultad:** Medium (Intermediate)
- **Link VulnHub:** [IA: Tornado machine](https://www.vulnhub.com/entry/ia-tornado,639/)

---

## Resumen ejecutivo

Tornado es una máquina boot2root de nivel intermedio que requiere encadenar vulnerabilidades:

1. **SQL Truncation** → Bypass de validación mediante truncamiento SQL
2. **LFI (Local File Inclusion)** → Inclusión de archivos locales para obtener información
3. **Privilege Escalation** → Escalada mediante configuraciones inseguras

---

## Contenido del directorio

```
Tornado/
├── README.md                      # Este archivo
├── Tornado.md                     # Guía completa paso a paso
├── Configuración Tornado IA.md    # Configuración de la VM
└── Imágenes/
    └── (capturas del proceso)
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **Web Enumeration**
- **Herramientas:** Nmap, Gobuster, Wappalyzer
- **Descubrimientos:** Directorios ocultos como `/bluesky`

### 2. **SQL Truncation Attack**
- **Técnica:** Bypass de validación mediante truncamiento de cadenas SQL
- **Impacto:** Creación de usuarios con privilegios elevados

### 3. **LFI (Local File Inclusion)**
- **Método:** Explotación de parámetros vulnerables
- **Archivos objetivo:** Configuración y credenciales

### 4. **Privilege Escalation**
- **Herramientas:** LinPEAS
- **Técnicas:** SUID binaries, sudo misconfiguration
- **Shell obtenida:** Usuario `root`

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos
- **Gobuster/ffuf** - Fuzzing de directorios
- **Wappalyzer** - Identificación de tecnologías
- **LinPEAS** - Enumeración de escalada de privilegios

---

## 🔗 Referencias y documentación relacionada

- [SQL Truncation Attack](../../OWASP%20TOP%2010/SQL%20Truncation/)
- [LFI (Local File Inclusion)](../../OWASP%20TOP%2010/LFI/)
- [LinEnum](../../Técnicas/Escalada%20de%20privilegios/Recursos%20escalada/LinEnum.md)
- [Escalada de privilegios Linux](../../Técnicas/Escalada%20de%20privilegios/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
