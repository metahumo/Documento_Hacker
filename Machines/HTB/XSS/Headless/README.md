# Headless - Hack The Box

![Dificultad](https://img.shields.io/badge/Dificultad-Easy-green)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-XSS%20%7C%20Command%20Injection-red)

---

## Información de la máquina

- **Nombre:** Headless
- **Plataforma:** Hack The Box
- **IP:** 10.10.11.8
- **SO:** Linux
- **Dificultad:** Easy
- **Link HTB:** [Headless machine](https://app.hackthebox.com/machines/Headless)

---

## Resumen ejecutivo

La explotación de Headless se centra en vulnerabilidades web y escalada de privilegios:

1. **Blind XSS** → Robo de cookies de administrador mediante inyección en el User-Agent
2. **Command Injection** → Ejecución remota de comandos en el panel de administración
3. **Privilege Escalation** → Explotación de script con permisos sudo mal configurado

---

## Contenido del directorio

```
Headless/
├── README.md           # Este archivo
├── Headless.md         # Guía completa paso a paso
└── Imagenes/
    └── (capturas del proceso)
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **Blind XSS (Cross-Site Scripting)**
- **Ubicación:** Header User-Agent
- **Payload:** Script malicioso para robo de cookies
- **Impacto:** Secuestro de sesión del administrador

### 2. **Command Injection**
- **Ubicación:** Panel de administración
- **Técnica:** Inyección de comandos del sistema
- **Shell obtenida:** Usuario de bajo privilegio

### 3. **Privilege Escalation**
- **Método:** Explotación de script con sudo sin rutas absolutas
- **Shell obtenida:** Usuario `root`

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos y servicios
- **BurpSuite** - Interceptación y análisis de peticiones HTTP
- **Netcat** - Reverse shell

---

## 🔗 Referencias y documentación relacionada

- [XSS (Cross-Site Scripting)](../../../../OWASP%20TOP%2010/XSS/)
- [Command Injection](../../../../OWASP%20TOP%2010/Command%20Injection/)
- [Escalada de privilegios Linux](../../../../Técnicas/Escalada%20de%20privilegios/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
