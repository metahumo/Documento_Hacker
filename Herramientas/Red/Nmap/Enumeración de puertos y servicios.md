
---
# Enumeración de Puertos y Servicios con Nmap

En esta sección agrupamos los puertos y servicios más comunes que podemos encontrar durante una fase de escaneo con Nmap. Esto nos permite organizarnos mejor y priorizar vectores de ataque según el tipo de servicio que identificamos.

Nuestro objetivo es clasificar los servicios por su funcionalidad, de manera que podamos aplicar técnicas específicas de enumeración para cada grupo.

---

## Agrupación de Puertos y Servicios

### Servicios Web (HTTP/HTTPS)

Estos servicios son los más comunes y representan puntos de entrada habituales en pruebas de penetración.

- Apache: 80 (HTTP), 443 (HTTPS)
- Nginx: 80, 443
- WordPress (normalmente sobre Apache/Nginx): 80, 443
- Tomcat/Jetty: 8080, 8443
- IIS (Internet Information Services): 80, 443, 8080

### Acceso Remoto

Servicios que permiten conectarse o controlar remotamente el sistema. Debemos enumerarlos con precaución.

- SSH (Secure Shell): 22
- Telnet: 23
- RDP (Remote Desktop Protocol): 3389
- VNC (Virtual Network Computing): 5900

### Transferencia de Archivos

Son usados para subir, descargar o sincronizar archivos. Pueden permitir acceso a archivos sensibles o ser vectores de ataque mediante configuraciones débiles.

- FTP (File Transfer Protocol): 21
- SFTP (sobre SSH): 22
- TFTP (Trivial FTP): 69
- Rsync: 873

### Compartición de Archivos y Directorios

Suelen encontrarse en entornos corporativos o redes internas.

- SMB (Server Message Block): 139, 445
- NFS (Network File System): 2049
- AFP (Apple Filing Protocol): 548

### Bases de Datos

En este grupo nos enfocamos en los servicios que almacenan información crítica. Pueden estar mal configurados o con credenciales por defecto.

- MySQL/MariaDB: 3306
- PostgreSQL: 5432
- Microsoft SQL Server (MSSQL): 1433
- Oracle Database: 1521
- MongoDB: 27017
- Redis: 6379

### Directorio y Autenticación

Sistemas que gestionan identidades y autenticaciones centralizadas. Pueden ser críticos en entornos empresariales.

- LDAP (Lightweight Directory Access Protocol): 389
- Kerberos: 88
- RADIUS: 1812
- TACACS+: 49

### Correo Electrónico

Podemos encontrar vectores de ataque como spoofing, relay abierto, fuga de información por banners, entre otros.

- SMTP: 25, 587, 465
- POP3: 110, 995
- IMAP: 143, 993

### VPN y Tunelización

Permiten el acceso remoto seguro, pero también son puntos de entrada si están mal configurados.

- OpenVPN: 1194
- PPTP: 1723
- L2TP: 1701
- IPSec/IKE: 500, 4500

### Otros Servicios de Administración

Herramientas de administración web o API que pueden exponerse accidentalmente.

- Webmin: 10000
- phpMyAdmin (sobre HTTP): 80, 8080, 443
- Jenkins: 8080
- Docker API: 2375, 2376
- Kubernetes API: 6443

---

## Siguientes pasos

Una vez identificamos qué puertos están abiertos y qué servicios están corriendo, procedemos a:

1. Usar scripts de Nmap (`-sC`, `--script`) específicos por servicio.
2. Conectarnos con herramientas como `netcat`, `telnet`, `hydra`, `nmap`, `rpcclient`, `enum4linux`, según el tipo de servicio.
3. Documentar posibles versiones vulnerables o configuraciones sospechosas.
4. Determinar vectores de ataque apropiados para cada uno.

Esta clasificación nos ayuda a optimizar el proceso de reconocimiento y priorizar aquellos servicios que son más propensos a ser explotables.

---
