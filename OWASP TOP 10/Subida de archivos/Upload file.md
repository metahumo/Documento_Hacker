# Abuso de Subidas de Archivos

## ¿Qué es?

> El abuso de subidas de archivos es una vulnerabilidad presente en muchas aplicaciones web que permite a un atacante subir archivos maliciosos al servidor. Si no se implementan controles adecuados, esto puede llevar a consecuencias graves como la ejecución remota de comandos.

Cuando una aplicación permite que los usuarios suban archivos (por ejemplo, imágenes de perfil o documentos), debemos asegurarnos de que estos archivos sean seguros. Si un atacante logra subir un archivo ejecutable, como un script PHP, y este se guarda en una carpeta accesible desde la web, podría ejecutarlo y tomar el control del servidor.

## ¿Cómo funciona un ataque?

1. Un atacante localiza una funcionalidad que permite subir archivos.
    
2. Intenta subir un archivo malicioso, por ejemplo `shell.php`.
    
3. Si la aplicación no valida correctamente el archivo, este se almacena en el servidor.
    
4. El atacante accede a la ruta del archivo (por ejemplo, `http://victima.com/uploads/shell.php`) y ejecuta comandos desde ahí.
    

## Técnicas comunes para evadir controles

- **Falsificación de la extensión del archivo:** el atacante sube un archivo llamado `shell.php.jpg`, esperando que solo se revise la parte final del nombre.
    
- **Falsificación del tipo MIME:** el atacante modifica el encabezado del archivo para que parezca una imagen (`image/jpeg`) aunque en realidad sea código malicioso.
    
- **Uso de doble extensión:** como `shell.php.png`, esperando que la validación solo mire `.png`.
    
- **Inclusión de caracteres especiales:** como `shell.php%00.jpg` (donde `%00` representa un carácter nulo que algunos lenguajes interpretan como el final del nombre).
    

## Ejemplo práctico

Supongamos que estamos desarrollando una aplicación web que permite a los usuarios subir su foto de perfil. Un atacante descubre que la aplicación solo verifica que la extensión del archivo sea `.jpg`, pero no analiza el contenido real del archivo ni restringe el tipo MIME.

El atacante crea un archivo llamado `shell.php`, que contiene:

```php
<?php system($_GET['cmd']); ?>
```

Luego cambia el nombre del archivo a `shell.php.jpg` y lo sube. El servidor lo guarda en `/uploads/`, accesible públicamente.

El atacante accede a:

```
http://nuestro-sitio.com/uploads/shell.php.jpg?cmd=ls
```

Y logra ejecutar el comando `ls` en nuestro servidor, obteniendo una lista de archivos del sistema.

## Ejemplo real

Un caso muy conocido fue el del **plugin TimThumb** de WordPress. Este plugin permitía generar miniaturas de imágenes desde URLs externas. Sin embargo, tenía una vulnerabilidad en el manejo de archivos, que permitía subir scripts PHP a través de direcciones URL maliciosas. Muchos sitios fueron comprometidos porque el archivo malicioso se ejecutaba en el servidor y daba acceso remoto al atacante.

## Laboratorio práctico

Para practicar todo lo anterior, podemos utilizar el siguiente laboratorio en Docker, desarrollado específicamente para experimentar con distintos escenarios de subida de archivos maliciosos:

**Repositorio en GitHub:**  
[https://github.com/moeinfatehi/file_upload_vulnerability_scenarios](https://github.com/moeinfatehi/file_upload_vulnerability_scenarios)

---
Aquí tienes en formato `.md` los tipos más comunes de **subida de archivos** que pueden presentar riesgos de seguridad en aplicaciones web:

---

# Tipos más comunes de Subida de Archivos

En las aplicaciones web existen varias formas de implementar la subida de archivos. Cada una presenta distintos riesgos y vectores de ataque si no se gestiona correctamente. A continuación, enumeramos los tipos más comunes:

## 1. Subida sin restricción (Unrestricted Upload)

La aplicación permite subir cualquier tipo de archivo sin verificar su contenido, extensión ni tipo MIME.

**Riesgo:** Alta posibilidad de que se suban scripts maliciosos como `.php`, `.aspx`, `.jsp`, etc.

## 2. Subida restringida por extensión (Extension-Based Filtering)

La aplicación permite subir solo archivos con ciertas extensiones, como `.jpg`, `.png` o `.pdf`.

**Riesgo:** Puede ser evadido mediante:

- Archivos con doble extensión (`shell.php.jpg`)
    
- Archivos renombrados manualmente
    
- Bypass con caracteres especiales (ej. `%00`, `%20`)
    

## 3. Subida restringida por tipo MIME (MIME Type Filtering)

La aplicación verifica el encabezado `Content-Type` enviado por el navegador (por ejemplo, `image/jpeg`).

**Riesgo:** Este encabezado puede ser fácilmente falsificado desde herramientas como Burp Suite o cURL.

## 4. Subida con validación del contenido (Content-Based Validation)

La aplicación analiza el contenido interno del archivo (por ejemplo, usando la firma mágica del archivo) para asegurarse de que sea realmente del tipo permitido.

**Riesgo:** Más seguro, pero si se implementa mal, aún se puede evadir con archivos híbridos (por ejemplo, un archivo que es a la vez una imagen válida y un script).

## 5. Subida y renombrado seguro en el servidor

La aplicación sube el archivo pero lo renombra automáticamente (ej. con un UUID) y lo guarda en un directorio inaccesible para la web.

**Riesgo:** Bajo. Esta práctica evita que el archivo pueda ser accedido directamente por un atacante, pero aún puede ser explotado si el archivo es procesado posteriormente sin validación.

## 6. Subida con transformación de archivos

El archivo subido es procesado (por ejemplo, convertido a otro formato o redimensionado) antes de almacenarse.

**Riesgo:** Bajo. Muy eficaz contra cargas maliciosas, ya que los scripts embebidos suelen eliminarse en la transformación.

## 7. Subida asincrónica con servicios externos (por ejemplo, a S3, Firebase)

La aplicación delega el almacenamiento de archivos a servicios externos y recibe una URL pública o privada.

**Riesgo:** Depende del control de acceso a esos archivos y de si se verifican antes de ser subidos.

---
