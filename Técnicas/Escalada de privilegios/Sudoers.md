
---
# Abusando de privilegios a nivel de Sudoers

## Introducción

En sistemas Linux, el archivo `/etc/sudoers` es fundamental para el control de acceso a tareas administrativas. A través de este archivo, se define qué usuarios o grupos pueden ejecutar comandos como superusuario u otros usuarios con privilegios especiales.

El comando `sudo` nos permite ejecutar tareas privilegiadas sin necesidad de cambiar completamente de usuario. Por ejemplo, podemos usar `sudo systemctl restart apache2` para reiniciar un servicio sin tener acceso directo a la cuenta `root`.

Sin embargo, si no se configura correctamente, este sistema puede ser abusado para **escalar privilegios** dentro de una máquina comprometida.

## Comprobación de privilegios con `sudo -l`

Una vez que obtenemos acceso a una máquina como usuario no privilegiado, es crucial comprobar si tenemos permisos especiales definidos en el archivo sudoers. Esto lo hacemos con:

```bash
sudo -l
````

Este comando nos devuelve una lista de comandos que el usuario puede ejecutar con `sudo` **sin necesidad de introducir la contraseña**, o bien con su contraseña, dependiendo de la configuración.

Por ejemplo, podríamos obtener una salida como la siguiente:

```
User ejemplo may run the following commands on this host:
    (ALL) NOPASSWD: /usr/bin/vim
```

Esto significa que el usuario `ejemplo` puede ejecutar `vim` como superusuario sin contraseña, lo cual puede ser explotado para escalar privilegios.

## Ejemplo práctico: Escalada con vim

Si vemos que podemos ejecutar `vim` con privilegios de root, como en el ejemplo anterior, podemos abusar de esto para abrir un shell con esos mismos privilegios.

Ejecutamos:

```bash
sudo vim -c '!bash'
```

Este comando abre una shell interactiva (`bash`) directamente desde Vim, pero con permisos de root.

## Recomendaciones de defensa

Para evitar este tipo de abuso, es recomendable seguir estas buenas prácticas:

- Restringir el uso de `sudo` a los usuarios estrictamente necesarios.
    
- Evitar permitir comandos con `NOPASSWD` salvo en casos justificados.
    
- Auditar periódicamente el archivo `/etc/sudoers` y los archivos en `/etc/sudoers.d/`.
    
- Usar herramientas como `auditd` para registrar y monitorizar el uso de `sudo`.
    

## Conclusión

La configuración del archivo sudoers es una de las áreas más críticas en la seguridad de un sistema Linux. Una mala configuración puede permitir que un atacante escale privilegios fácilmente. Como analistas ofensivos, debemos revisar cuidadosamente los privilegios disponibles mediante `sudo -l` y, como administradores, debemos minimizar la superficie de ataque configurando `sudo` de forma segura.

---

