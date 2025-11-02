# Titanic - Hack The Box

![Dificultad](https://img.shields.io/badge/Dificultad-Easy-green)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-LFI%20%7C%20CVE--2024--41817-red)

---

## Información de la máquina

- **Nombre:** Titanic
- **Plataforma:** Hack The Box
- **IP:** 10.10.11.55
- **SO:** Linux
- **Dificultad:** Easy
- **Link HTB:** [Titanic machine](https://app.hackthebox.com/machines/Titanic)

---

## Resumen ejecutivo

La explotación de Titanic combina vulnerabilidades web con CVE reciente:

1. **LFI (Local File Inclusion)** → Lectura de archivos sensibles del sistema
2. **Docker Enumeration** → Exploración de contenedores y servicios internos
3. **ImageMagick CVE-2024-41817** → Escalada de privilegios mediante vulnerabilidad reciente

---

## Contenido del directorio

```
Titanic/
├── README.md           # Este archivo
├── Titanic.md          # Guía completa paso a paso
└── (otras capturas y recursos)
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **LFI (Local File Inclusion)**
- **Vector:** Directory traversal
- **Path traversal:** `../../../etc/passwd`
- **Archivos exfiltrados:** Archivos de configuración y credenciales

### 2. **Docker/Container Exploration**
- **Método:** Enumeración de servicios internos
- **Herramientas:** Docker commands, inspección de configuración

### 3. **Privilege Escalation - ImageMagick CVE-2024-41817**
- **Vulnerabilidad:** CVE-2024-41817
- **Software afectado:** ImageMagick
- **Técnica:** Explotación de vulnerabilidad reciente
- **Shell obtenida:** Usuario `root`

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos y servicios
- **BurpSuite** - Testing de LFI
- **Docker** - Enumeración de contenedores
- **Exploit para CVE-2024-41817** - Escalada de privilegios

---

## 🔗 Referencias y documentación relacionada

- [LFI (Local File Inclusion)](../../../../OWASP%20TOP%2010/LFI/)
- [Docker Security](../../../../Técnicas/Docker/)
- [CVE-2024-41817](https://nvd.nist.gov/vuln/detail/CVE-2024-41817)
- [Escalada de privilegios Linux](../../../../Técnicas/Escalada%20de%20privilegios/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
