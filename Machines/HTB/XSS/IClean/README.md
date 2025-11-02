# IClean - Hack The Box

![Dificultad](https://img.shields.io/badge/Dificultad-Medium-yellow)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-XSS%20%7C%20SSTI-red)

---

## Información de la máquina

- **Nombre:** IClean
- **Plataforma:** Hack The Box
- **IP:** 10.10.11.12
- **SO:** Linux
- **Dificultad:** Medium
- **Link HTB:** [IClean machine](https://app.hackthebox.com/machines/IClean)

---

## Resumen ejecutivo

La explotación de IClean combina vulnerabilidades web modernas con escalada de privilegios:

1. **XSS (Cross-Site Scripting)** → Robo de cookies de sesión del administrador
2. **SSTI (Server-Side Template Injection)** → Explotación de Jinja2 para RCE
3. **Privilege Escalation** → Abuso de permisos sudo con qpdf

---

## Contenido del directorio

```
IClean/
├── README.md           # Este archivo
├── IClean.md           # Guía completa paso a paso
└── Imágenes/
    └── (capturas del proceso)
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **XSS (Cross-Site Scripting)**
- **Ubicación:** Aplicación web Flask
- **Impacto:** Robo de cookies de administrador

### 2. **SSTI (Server-Side Template Injection)**
- **Motor de plantillas:** Jinja2
- **Payload:** Inyección de código Python
- **Resultado:** RCE (Remote Code Execution)

### 3. **Privilege Escalation**
- **Método:** Abuso de permisos sudo con qpdf
- **Shell obtenida:** Usuario `root`

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos y servicios
- **Wappalyzer** - Identificación de tecnologías web
- **BurpSuite** - Interceptación y análisis de peticiones HTTP
- **PayloadsAllTheThings** - Repositorio de payloads SSTI

---

## 🔗 Referencias y documentación relacionada

- [XSS (Cross-Site Scripting)](../../../../OWASP%20TOP%2010/XSS/)
- [SSTI (Server-Side Template Injection)](../../../../OWASP%20TOP%2010/SSTI/)
- [Escalada de privilegios Linux](../../../../Técnicas/Escalada%20de%20privilegios/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
