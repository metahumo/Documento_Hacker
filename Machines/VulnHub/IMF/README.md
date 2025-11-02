# IMF - VulnHub

![Dificultad](https://img.shields.io/badge/Dificultad-Medium-yellow)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-Web%20Exploitation%20%7C%20SQL%20Injection-red)

---

## Información de la máquina

- **Nombre:** IMF
- **Plataforma:** VulnHub
- **SO:** Linux (Ubuntu)
- **Dificultad:** Medium (Beginner to Moderate)
- **Link VulnHub:** [IMF machine](https://www.vulnhub.com/series/imf,95/)

---

## Resumen ejecutivo

IMF es una máquina CTF con estructura de flags progresivas:

1. **Web Enumeration** → Descubrimiento de directorios y archivos ocultos
2. **SQL Injection** → Explotación de vulnerabilidades de inyección SQL
3. **Privilege Escalation** → Escalada mediante técnicas estándar de Linux

---

## Contenido del directorio

```
IMF/
├── README.md                    # Este archivo
├── IMF.md                       # Guía completa paso a paso
├── Ingeniería Inversa.md        # Documentación sobre reverse engineering
├── Script.md                    # Scripts utilizados
└── Imágenes/
    └── (capturas del proceso)
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **Network Enumeration**
- **Herramientas:** Nmap, netdiscover
- **Descubrimientos:** Puertos abiertos y servicios

### 2. **Web Exploitation**
- **Técnicas:** Directory brute-forcing, análisis de código fuente
- **Herramientas:** Gobuster, Dirbuster, navegador

### 3. **SQL Injection**
- **Ubicación:** Formularios web vulnerables
- **Impacto:** Extracción de información sensible

### 4. **Privilege Escalation**
- **Método:** Enumeración de SUID, kernel exploits
- **Herramientas:** LinPEAS, manual enumeration
- **Shell obtenida:** Usuario `root`

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap/Netdiscover** - Descubrimiento de red
- **Gobuster/Dirbuster** - Enumeración web
- **BurpSuite** - Testing de vulnerabilidades web
- **LinPEAS** - Enumeración de escalada de privilegios

---

## 🔗 Referencias y documentación relacionada

- [SQL Injection](../../../OWASP%20TOP%2010/SQLi/)
- [Web Exploitation](../../../OWASP%20TOP%2010/)
- [Ingeniería Inversa](./Ingeniería%20Inversa.md)
- [Escalada de privilegios Linux](../../../Técnicas/Escalada%20de%20privilegios/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
