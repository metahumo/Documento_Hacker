# Importancia de `disable_functions` y `file_uploads` en un Pentesting

En un pentest, revisar un `info.php` nos da la configuración de PHP y nos ayuda a estimar vectores y alcance de explotación. Aquí explicamos brevemente por qué nos interesa especialmente `disable_functions` y `file_uploads`.

## `disable_functions`
- **Qué es:** directiva que deshabilita funciones de PHP potencialmente peligrosas (p. ej. `exec`, `system`, `shell_exec`, `passthru`, `popen`, `proc_open`).
- **Por qué nos importa:**  
  - Si aparece como `no value` significa que **no hay funciones deshabilitadas** → en caso de RCE tendremos más posibilidades de ejecutar comandos del SO directamente.  
  - Si contiene funciones, se reduce el impacto de un RCE pero **aún puede haber funciones alternativas** o combinaciones que permitan ejecución (bypasses).
- **Qué comprobamos:**  
  - Ver si están deshabilitadas las funciones de ejecución de procesos y aquellas usadas para interactuar con el SO.  
  - Buscar funciones menos obvias que a menudo se olvidan (`proc_open`, `popen`, `pcntl_exec`, `expect_*`) y funciones que permitan escribir/leer ficheros (`file_put_contents`, `fopen`) si no están deshabilitadas.
- **Implicación práctica:** conocer `disable_functions` nos ayuda a planear payloads no destructivos en laboratorio, decidir si intentamos RCE directo, buscar vectores alternativos (SSRF, file inclusion, comandos vía DB, etc.) o centrar el ataque en escalado lateral.

## `file_uploads`
- **Qué es:** directiva que habilita o deshabilita la capacidad de PHP para manejar subidas de ficheros (`On`/`Off`).
- **Por qué nos importa:**  
  - Si está **`On`**, podemos probar cargas de ficheros maliciosos (por ejemplo shells web, scripts de prueba — siempre en laboratorio) o subir ficheros para pivotar a otras vulnerabilidades.  
  - Si está **`Off`**, se cierra una vía directa común; aun así, pueden existir otros caminos (vulnerabilidades en formularios que escriban ficheros, LFI que incluya ficheros subidos por otros mecanismos, o subidas a través de servicios externos).
- **Qué comprobamos:**  
  - Estado (`On`/`Off`).  
  - Otras directivas relacionadas: `upload_max_filesize`, `post_max_size`, `max_file_uploads`, y permisos en directorios destino.  
  - Validación del lado servidor (tipo, extensión, renombrado, comprobación MIME) y existencia de controles adicionales (whitelists, sanitización).
- **Implicación práctica:** si `file_uploads` está activo, priorizamos pruebas controladas de subida (en laboratorio) y validamos si el pipeline de subida permite ejecución (por ejemplo, subir `.php` renombrado o bypass de extensión) — si está desactivado, buscamos cadenas que permitan escribir ficheros de otra forma.

## Conclusión rápida
- `disable_functions` nos indica **qué capacidad de ejecución está bloqueada**, condicionando nuestros métodos de explotación y evasión.  
- `file_uploads` nos indica si **la ruta de subida de ficheros** es viable como vector para persistencia o ejecución.  
- Juntas, estas directivas nos permiten evaluar el **nivel de endurecimiento** y priorizar pruebas: RCE directo, bypasses, vectores de file inclusion, o técnicas alternativas (SSRF, SQL import, etc.).
