# Backend - Hack The Box

![Dificultad](https://img.shields.io/badge/Dificultad-Medium-yellow)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-API%20Exploitation%20%7C%20JWT-red)

---

## Información de la máquina

- **Nombre:** Backend
- **Plataforma:** Hack The Box
- **IP:** 10.10.11.161
- **SO:** Linux
- **Dificultad:** Medium
- **Link HTB:** [Backend machine](https://app.hackthebox.com/machines/Backend)

---

## Resumen ejecutivo

La explotación de Backend se centra en vulnerabilidades de API y autenticación:

1. **API Enumeration** → Descubrimiento de endpoints administrativos mediante fuzzing
2. **JWT Manipulation** → Modificación de tokens para bypass de autenticación
3. **Privilege Escalation** → Análisis de logs para obtención de credenciales de root

---

## Contenido del directorio

```
Backend/
├── README.md           # Este archivo
├── Backend.md          # Guía completa paso a paso
└── Imágenes/
    └── (capturas del proceso)
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **API Enumeration**
- **Framework:** FastAPI (Python)
- **Técnica:** Fuzzing de endpoints con wfuzz
- **Descubrimientos:** Rutas administrativas ocultas

### 2. **Authentication Bypass**
- **Método:** Manipulación de tokens JWT
- **Herramienta:** JWT.io o jwt_tool
- **Impacto:** Acceso a funcionalidades administrativas

### 3. **Command Execution**
- **Técnica:** Explotación de endpoints administrativos
- **Shell obtenida:** Usuario de bajo privilegio

### 4. **Privilege Escalation**
- **Método:** Análisis de archivos de log
- **Descubrimiento:** Credenciales de root en logs
- **Shell obtenida:** Usuario `root`

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos y servicios
- **Wfuzz** - Fuzzing de API endpoints
- **BurpSuite** - Interceptación y manipulación de peticiones
- **JWT.io** - Decodificación y manipulación de tokens JWT
- **Curl/jq** - Interacción con la API

---

## 🔗 Referencias y documentación relacionada

- [API Security](../../../../OWASP%20TOP%2010/API/)
- [JWT (JSON Web Tokens)](../../../../Técnicas/JWT/)
- [Escalada de privilegios Linux](../../../../Técnicas/Escalada%20de%20privilegios/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
