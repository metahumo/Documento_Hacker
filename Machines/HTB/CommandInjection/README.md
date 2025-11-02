# Previse - Hack The Box

![Dificultad](https://img.shields.io/badge/Dificultad-Easy-green)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-Command%20Injection%20%7C%20PATH%20Hijacking-red)

---

## Información de la máquina

- **Nombre:** Previse
- **Plataforma:** Hack The Box
- **IP:** 10.10.11.104
- **SO:** Linux
- **Dificultad:** Easy
- **Link HTB:** [Previse machine](https://app.hackthebox.com/machines/Previse)

---

## Resumen ejecutivo

La explotación de Previse se centra en vulnerabilidades de inyección:

1. **Command Injection** → RCE mediante inyección de comandos en funcionalidad de logs
2. **Password Cracking** → Obtención de credenciales mediante hash cracking
3. **PATH Hijacking** → Escalada de privilegios explotando rutas relativas en scripts

---

## Contenido del directorio

```
Previse/
├── README.md           # Este archivo
├── Previse.md          # Guía completa paso a paso
└── Imágenes/
    └── (capturas del proceso)
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **Command Injection**
- **Ubicación:** Endpoint de gestión de logs
- **Payload:** Concatenación de comandos con `;` o `&&`
- **Shell obtenida:** Usuario `www-data`

### 2. **Database Enumeration**
- **Método:** Acceso a credenciales de base de datos
- **Descubrimientos:** Hashes de contraseñas de usuarios

### 3. **Password Cracking**
- **Hash type:** MD5 crypt
- **Herramienta:** Hashcat o John the Ripper
- **Credenciales obtenidas:** Usuario del sistema

### 4. **PATH Hijacking**
- **Técnica:** Explotación de comandos ejecutados con rutas relativas
- **Comando vulnerable:** `gzip` sin ruta absoluta
- **Shell obtenida:** Usuario `root`

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos y servicios
- **BurpSuite** - Interceptación de peticiones para command injection
- **Hashcat/John** - Cracking de contraseñas
- **MySQL** - Enumeración de base de datos

---

## 🔗 Referencias y documentación relacionada

- [Command Injection](../../../../OWASP%20TOP%2010/Command%20Injection/)
- [PATH Hijacking](../../../../Técnicas/Escalada%20de%20privilegios/PATH%20Hijacking.md)
- [Escalada de privilegios Linux](../../../../Técnicas/Escalada%20de%20privilegios/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
