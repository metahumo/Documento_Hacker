
---
# Cheat Sheet: Comandos para Escalada de Privilegios en Linux

---

## Sudo

```bash
sudo -l
# Listar comandos permitidos por sudo para el usuario actual

sudo -l -U usuario
# Listar comandos permitidos para otro usuario

sudo -u usuario comando
# Ejecutar comando como otro usuario (si está permitido)
````

---

## SUID / SGID

```bash
find / -perm -4000 -type f 2>/dev/null
# Buscar archivos con bit SUID activo

find / -perm -2000 -type f 2>/dev/null
# Buscar archivos con bit SGID activo

ls -l /path/to/suid/file
# Ver permisos detallados de un archivo SUID/SGID
```

---

## Archivos Cron y Tareas Programadas

```bash
cat /etc/crontab
# Ver cron jobs del sistema

ls -la /etc/cron.*
# Listar directorios de cron

crontab -l
# Ver cron jobs del usuario actual

crontab -u usuario -l
# Ver cron jobs de otro usuario
```

---

## Capabilities (Linux Capabilities)

```bash
getcap -r / 2>/dev/null
# Listar archivos con capacidades especiales en todo el sistema

getcap /path/to/file
# Ver capacidades de un archivo específico
```

---

## Comandos útiles para recolectar información

```bash
uname -a
# Información del sistema operativo y kernel

id
# Información del usuario actual

groups
# Grupos del usuario actual

ps aux
# Procesos en ejecución

env
# Variables de entorno

mount
# Sistemas de archivos montados

ip a
# Configuración de red

cat /etc/passwd
# Usuarios del sistema

cat /etc/shadow
# Contraseñas hash (requiere privilegios)
```

---

## Buscar ficheros con permisos inseguros

```bash
find / -writable -type d 2>/dev/null
# Directorios con permisos de escritura

find / -writable -type f 2>/dev/null
# Archivos con permisos de escritura
```

---

## Otros comandos para enumeración

```bash
ss -tulpn
# Puertos abiertos y servicios escuchando

netstat -tulpen
# Información detallada de conexiones y puertos abiertos

ls -la /home/
# Listar directorios home y permisos
```

---

## Ejemplo para buscar binarios que pueden ser explotados

```bash
find / -type f -executable -perm -4000 2>/dev/null
# Buscar binarios ejecutables con SUID
```

---

## Escalar privilegios con exploits

```bash
# Buscar vulnerabilidades conocidas con búsqueda rápida
searchsploit nombre_vulnerabilidad

# Usar herramientas automáticas
linenum.sh
linpeas.sh
```

- [LinEnum](Recursos%20escalada/LinEnum.md)
- [LinPEAS](Recursos%20escalada/LinPEAS.md)
- [Metasploit](../../../../Herramientas/Metasploit.md.md)

---
