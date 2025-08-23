# Redirección Abierta (Open Redirect)

La redirección abierta, conocida también como **Open Redirect**, es una vulnerabilidad frecuente en aplicaciones web. Esta se presenta cuando una aplicación permite que el usuario sea redirigido a una URL externa sin validar adecuadamente el destino. Como resultado, los atacantes pueden aprovechar este comportamiento para redirigir a las víctimas hacia sitios maliciosos.

## ¿Qué ocurre en una redirección abierta?

Cuando una aplicación permite que una URL de redireccionamiento sea manipulada por un parámetro (por ejemplo, `?next=` o `?url=`) y no valida ni restringe su valor, se abre una puerta para que un atacante pueda sustituir el destino legítimo por uno malicioso.

Esto no solo puede confundir al usuario, sino que también puede facilitar ataques de **phishing**, **robo de credenciales**, o incluso la propagación de **malware**.

## Ejemplo práctico en un entorno controlado

Supongamos que estamos probando la siguiente URL en una aplicación de laboratorio:

```
http://vulnerable-app.com/login?redirect=http://legit-site.com/dashboard
```

Después de iniciar sesión, el usuario es redirigido a `http://legit-site.com/dashboard`. Pero si no se valida ese parámetro, podríamos modificarlo así:

```
http://vulnerable-app.com/login?redirect=http://malicious-site.com/phishing
```

Si la aplicación permite esta redirección sin validación, estaríamos frente a un caso de redirección abierta.

En nuestras prácticas, vamos a desplegar y analizar estas tres versiones del laboratorio:

- [Open Redirect 1](https://github.com/blabla1337/skf-labs/tree/master/nodeJs/Url-redirection)
    
- [Open Redirect 2](https://github.com/blabla1337/skf-labs/tree/master/nodeJs/Url-redirection-harder)
    
- [Open Redirect 3](https://github.com/blabla1337/skf-labs/tree/master/nodeJs/Url-redirection-harder2)
    

En ellos, vamos a explorar desde los casos más simples hasta implementaciones que ya incluyen restricciones más avanzadas que debemos aprender a analizar y evadir.

## Ejemplo real

En 2020, un investigador de seguridad descubrió que un subdominio de un sitio muy conocido (`facebook.com`) era vulnerable a Open Redirect. El parámetro vulnerable permitía redireccionar a sitios externos sin validación. Los atacantes usaban este tipo de enlaces en campañas de phishing, aprovechando que el dominio inicial parecía legítimo (`facebook.com`) para engañar al usuario y lograr que hiciera clic.

Esto demuestra que incluso grandes plataformas pueden ser afectadas por esta vulnerabilidad si no se toman las medidas adecuadas.

## Ejemplo real

En 2014, PayPal fue víctima de una vulnerabilidad de redirección abierta. Un atacante podía crear un enlace que aparentaba ser legítimo, como:

```bash
https://www.paypal.com/cgi-bin/webscr?cmd=_redirect&return=https://sitio-falso.com
```

Los usuarios que hacían clic en ese enlace eran redirigidos desde el dominio oficial de PayPal hacia una página falsa, diseñada para capturar credenciales o datos de tarjeta.

La gravedad del caso se debe a que el dominio de PayPal era confiable para los usuarios. La redirección se aprovechó para lanzar campañas de phishing muy creíbles.

## Cómo prevenir la redirección abierta

Como desarrolladores o pentesters, debemos tener en cuenta las siguientes buenas prácticas:

- Validar siempre las URLs de redirección, asegurando que solo se permita redirigir a destinos internos o predefinidos.
    
- Evitar usar URLs absolutas como parámetros. Es preferible utilizar identificadores o rutas relativas internas (por ejemplo, `?next=/perfil` en lugar de `?next=http://otro-sitio.com`).
    
- Si se debe redirigir a URLs externas, mantener una lista blanca de destinos válidos.
    
- Codificar adecuadamente los parámetros y filtrar cualquier carácter extraño o sospechoso.
    

## Conclusión

Las redirecciones abiertas pueden parecer inofensivas, pero son una puerta de entrada común para ataques de ingeniería social. En nuestras prácticas, aprenderemos a identificarlas, explotarlas y aplicar las medidas necesarias para prevenirlas.

---
