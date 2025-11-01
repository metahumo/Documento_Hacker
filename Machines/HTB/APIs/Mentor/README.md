# Mentor - Hack The Box

![Dificultad](https://img.shields.io/badge/Dificultad-Medium-yellow)
![SO](https://img.shields.io/badge/SO-Linux-blue)
![Técnicas](https://img.shields.io/badge/Técnicas-API%20Exploitation%20%7C%20SNMP-red)

---

## Información de la máquina

- **Nombre:** Mentor
- **Plataforma:** Hack The Box
- **IP:** 10.10.11.193
- **SO:** Linux
- **Dificultad:** Medium
- **Link HTB:** [Mentor machine](https://app.hackthebox.com/machines/Mentor)

---

## Resumen ejecutivo

La explotación de Mentor involucra enumeración avanzada y pivoting:

1. **SNMP Enumeration** → Descubrimiento de credenciales mediante snmpwalk
2. **API Exploitation** → Explotación de vulnerabilidades en API REST
3. **Command Injection** → RCE mediante inyección de comandos
4. **Privilege Escalation** → Escalada mediante Docker y credenciales de base de datos

---

## Contenido del directorio

```
Mentor/
├── README.md           # Este archivo
├── Mentor.md           # Guía completa paso a paso
└── Imágenes/
    └── (capturas del proceso)
```

---

## Técnicas y vulnerabilidades explotadas

### 1. **SNMP Enumeration**
- **Protocolo:** SNMP (Simple Network Management Protocol)
- **Herramienta:** snmpwalk
- **Descubrimientos:** Credenciales y configuración del sistema

### 2. **API Exploitation**
- **Framework:** API REST
- **Técnica:** Fuzzing y explotación de endpoints
- **Impacto:** Acceso a funcionalidades administrativas

### 3. **Command Injection**
- **Ubicación:** API vulnerable
- **Shell obtenida:** Usuario de bajo privilegio

### 4. **Multi-User Pivoting**
- **Método:** Enumeración de bases de datos y contenedores Docker
- **Shell obtenida:** Usuario `root`

---

## Recursos y herramientas utilizadas

### Herramientas principales
- **Nmap** - Escaneo de puertos y servicios
- **snmpwalk** - Enumeración SNMP
- **Wfuzz** - Fuzzing de API
- **BurpSuite** - Interceptación de peticiones

---

## 🔗 Referencias y documentación relacionada

- [SNMP Enumeration](../../../../Herramientas/Red/SNMP/)
- [API Security](../../../../OWASP%20TOP%2010/API/)
- [Command Injection](../../../../OWASP%20TOP%2010/Command%20Injection/)
- [Escalada de privilegios Linux](../../../../Técnicas/Escalada%20de%20privilegios/)

---

## Disclaimer legal

Este material tiene **fines exclusivamente educativos**. La explotación de sistemas sin autorización expresa es **ilegal**. Practica únicamente en:
- Laboratorios autorizados (HTB, VulnHub, PentesterLab)
- Máquinas virtuales propias
- Entornos de testing con permiso escrito

**No nos hacemos responsables del uso indebido de esta información.**
