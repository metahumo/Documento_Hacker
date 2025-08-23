# Server-Side Template Injection (SSTI)

## ¿Qué es SSTI?

SSTI (Server-Side Template Injection) es una vulnerabilidad que ocurre cuando una aplicación web **interpreta y ejecuta contenido malicioso dentro de un motor de plantillas del lado del servidor**.

Esto puede permitir a un atacante:

- Acceder a variables del sistema.
- Ejecutar comandos del sistema operativo.
- Escalar privilegios si el motor lo permite.

---

## ¿Por qué ocurre?

En muchos frameworks web, se usan motores de plantillas para generar HTML dinámico (como Jinja2, Twig, EJS, etc.). Si una aplicación introduce datos del usuario directamente en estas plantillas sin validación, un atacante puede inyectar código en ellas.

---

## Ejemplo práctico (básico de testeo)

Supongamos que tenemos un campo de búsqueda que devuelve el siguiente HTML:

```html
<h2>Resultados para: {{ búsqueda }}</h2>
````

Si se inyecta lo siguiente en el campo de búsqueda:

```txt
{{7*7}}
```

Y el resultado devuelto es:

```
Resultados para: 49
```

Entonces, es muy probable que el motor esté **evaluando expresiones**, lo que indica una **posible SSTI**.

Este comportamiento indica que estamos ante un motor vulnerable, por ejemplo, `Jinja2` en Flask (Python).

---

## Ejemplo más realista

### Supuesto escenario en Flask (Python) con Jinja2

Código del servidor (vulnerable):

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/perfil")
def perfil():
    nombre = request.args.get("nombre", "Invitado")
    plantilla = f"<h1>Hola, {nombre}</h1>"
    return render_template_string(plantilla)
```

Un atacante accede a:

```
http://example.com/perfil?nombre={{7*7}}
```

Y obtiene:

```
Hola, 49
```

Lo que confirma la **vulnerabilidad SSTI**. Desde aquí, el atacante puede ir más allá probando payloads como:

```txt
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

Esto puede conducir a ejecución de código en el servidor dependiendo del entorno.

---

## Medidas de prevención

* No renderizar datos del usuario directamente con `render_template_string()` o plantillas sin sanitizar.
* Usar funciones de escape y autoescaping (según el motor).
* Validar y sanear toda entrada del usuario.
* Utilizar linters y escáneres de seguridad para detectar SSTI.

---

## Recursos recomendados

* [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
* [PortSwigger Web Security Academy - SSTI](https://portswigger.net/web-security/server-side-template-injection)

---
