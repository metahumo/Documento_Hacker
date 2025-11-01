# MyExpense - VulnHub

![Dificultad](https://img.shields.io/badge/Dificultad-Easy-green)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-XSS%20%7C%20SQL%20Injection-red)

---

## Información de la máquina

- **Nombre:** MyExpense
- **Plataforma:** VulnHub
- **SO:** Linux
- **Dificultad:** Easy (Easy to Intermediate)
- **Link VulnHub:** [MyExpense machine](https://www.vulnhub.com/series/myexpense,265/)

---

## Resumen ejecutivo

MyExpense es una aplicación web deliberadamente vulnerable para practicar múltiples técnicas:

1. **XSS (Cross-Site Scripting)** → Robo de cookies mediante Stored XSS
2. **SQL Injection** → Explotación de inyecciones SQL en formularios
3. **IDOR/CSRF** → Manipulación de referencias de objetos y peticiones falsificadas

---

## Contenido del directorio

```
MyExpense.md           # Guía completa paso a paso
README.md              # Este archivo
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **Network Enumeration**
- **Herramientas:** Nmap, Netdiscover
- **Descubrimientos:** IP de la máquina y servicios web

### 2. **Stored XSS**
- **Ubicación:** Campos de formulario (ej: First Name)
- **Payload:** JavaScript malicioso para robo de cookies
- **Impacto:** Secuestro de sesión del administrador

### 3. **SQL Injection**
- **Ubicación:** Formularios sin validación
- **Técnica:** Classic SQL injection
- **Impacto:** Extracción de datos sensibles

### 4. **IDOR (Insecure Direct Object Reference)**
- **Método:** Manipulación de parámetros de sesión
- **Impacto:** Acceso a funcionalidades de otros usuarios

### 5. **Session Hijacking**
- **Técnica:** Uso de cookies robadas vía XSS
- **Resultado:** Acceso como administrador

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap/Netdiscover** - Descubrimiento de red
- **Dirb/Gobuster** - Enumeración de directorios
- **BurpSuite** - Interceptación y análisis de peticiones
- **Python HTTP Server** - Recepción de cookies exfiltradas

---

## 🔗 Referencias y documentación relacionada

- [XSS (Cross-Site Scripting)](../../OWASP%20TOP%2010/XSS/)
- [SQL Injection](../../OWASP%20TOP%2010/SQLi/)
- [IDOR](../../OWASP%20TOP%2010/IDOR/)
- [CSRF](../../OWASP%20TOP%2010/CSRF/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
