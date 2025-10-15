
---
## ¿Qué es AngularJS?

> AngularJS es un **framework de JavaScript** desarrollado originalmente por **Google** en 2010. Su objetivo principal es facilitar la creación de **aplicaciones web dinámicas** mediante el uso de **HTML extendido** con directivas personalizadas y **data binding bidireccional** (two-way data binding). Esto permite que los datos entre el modelo y la vista estén sincronizados automáticamente sin necesidad de manipular el DOM de forma manual.

Fue uno de los primeros frameworks en introducir un enfoque declarativo para construir interfaces interactivas, y aunque hoy ha sido reemplazado por Angular (su versión reescrita en TypeScript), **AngularJS sigue siendo usado en muchos entornos heredados (legacy)**, lo que lo convierte en un objetivo interesante desde el punto de vista de la seguridad.

Aquí tienes el documento en formato **Markdown (.md)** tal como pediste:

---

# AngularJS: Perspectiva desde el Pentesting y el Bug Hunting

## ¿Qué es AngularJS?

AngularJS es un **framework de JavaScript** desarrollado originalmente por **Google** en 2010. Su objetivo principal es facilitar la creación de **aplicaciones web dinámicas** mediante el uso de **HTML extendido** con directivas personalizadas y **data binding bidireccional** (two-way data binding). Esto permite que los datos entre el modelo y la vista estén sincronizados automáticamente sin necesidad de manipular el DOM de forma manual.

Fue uno de los primeros frameworks en introducir un enfoque declarativo para construir interfaces interactivas, y aunque hoy ha sido reemplazado por Angular (su versión reescrita en TypeScript), **AngularJS sigue siendo usado en muchos entornos heredados (legacy)**, lo que lo convierte en un objetivo interesante desde el punto de vista de la seguridad.

---

## Importancia para un Pentester y Bug Hunter

Desde una perspectiva ofensiva, AngularJS introduce una serie de mecanismos y comportamientos que pueden derivar en vulnerabilidades si no se gestionan correctamente. Entre los aspectos más relevantes destacan:

### 1. Evaluación de Expresiones Dinámicas

AngularJS permite el uso de expresiones entre doble llave `{{ }}` que se evalúan en tiempo de ejecución dentro del contexto de la aplicación.  
Por ejemplo:

```html
<div ng-app>
  {{ 1 + 2 }}
</div>
```

renderizará el valor `3` en el navegador.  
Sin embargo, este mismo mecanismo puede ser explotado si los datos no están debidamente sanitizados. Un atacante podría inyectar código como:

```html
{{constructor.constructor('alert(1)')()}}
```

Este payload aprovecha la capacidad de AngularJS para acceder al objeto `Function` a través del `constructor`, ejecutando código arbitrario JavaScript dentro del navegador del usuario.

---

### 2. Contextos de Inyección Comunes

Un pentester debe evaluar los puntos de entrada donde se reflejan datos controlados por el usuario en el DOM y que son procesados por AngularJS. Algunos ejemplos típicos incluyen:

- Parámetros de búsqueda (`?q=valor`) renderizados dentro de una vista Angular.
    
- Atributos de directivas (`ng-app`, `ng-model`, `ng-bind-html`, `ng-init`, etc.).
    
- Fragmentos HTML que se cargan dinámicamente y son compilados por AngularJS.
    

Cada uno de estos contextos puede servir como vector para **DOM-based XSS** o **AngularJS template injection**.

---

### 3. Versiones Vulnerables y Sandbox Bypass

Las versiones antiguas de AngularJS (anteriores a 1.6) contenían múltiples vulnerabilidades que permitían **romper el sandbox** de seguridad del framework y ejecutar JavaScript arbitrario incluso en entornos parcialmente filtrados.

Por ejemplo, payloads que antes no eran posibles con sanitización básica podían ejecutarse debido a debilidades en el parser de expresiones.  
Un bug hunter debe conocer las **diferencias entre versiones** y los **métodos de evasión** más comunes, ya que en programas de bug bounty aún es frecuente encontrar sitios que usan AngularJS 1.3.x o 1.4.x.

---

## Riesgos más Comunes

- **DOM-based XSS** a través de expresiones AngularJS.
    
- **Template Injection** si el framework compila dinámicamente contenido HTML sin sanitización.
    
- **Deserialización insegura** de datos dentro de directivas o controladores.
    
- **Uso de versiones antiguas sin parches** que contienen vulnerabilidades sandbox escape.
    


---

## Análisis de la Superficie de Ataque

En nuestro proceso, identificamos que AngularJS puede ampliar la superficie de ataque principalmente por su naturaleza de single-page application (SPA) y por la forma en que manipula el DOM. Prestamos especial atención a las siguientes áreas:

- **Inyección de plantillas**: AngularJS permite la interpolación de datos y el uso de expresiones dentro del HTML. Si no se realiza una adecuada sanitización de entradas, podemos explotar vulnerabilidades como la inyección de expresiones AngularJS, que puede derivar en ejecución de código arbitrario en el navegador de la víctima.
- **XSS (Cross-Site Scripting)**: Aunque AngularJS implementa medidas para mitigar XSS, como el uso de `$sce` (Strict Contextual Escaping), aún hemos descubierto que su uso incorrecto o el deshabilitar mecanismos de seguridad puede abrir puertas a la ejecución de scripts maliciosos.
- **Bypass de filtros**: Durante nuestras pruebas, ponemos a prueba los filtros y validaciones implementados, buscando maneras de sortear las restricciones usando técnicas como la doble interpolación o el uso de expresiones no convencionales.
- **Exposición de lógica cliente**: AngularJS expone parte de la lógica de la aplicación en el lado cliente. Analizamos los archivos JavaScript accesibles públicamente para intentar comprender la lógica de negocio, descubrir endpoints ocultos, y detectar posibles rutas no protegidas.

## Metodologías de Pruebas

Nuestra aproximación se basa en:

- **Revisión de código fuente**: Siempre que es posible, revisamos el código fuente de las aplicaciones AngularJS, ya sea de forma estática o dinámica, buscando patrones inseguros como el uso de `ng-bind-html`, el empleo excesivo de `$eval`, o la desactivación de la sanitización.
- **Pruebas manuales y automatizadas**: Utilizamos herramientas proxy y navegadores para inyectar payloads en los puntos de entrada de la aplicación, evaluando cómo AngularJS procesa y renderiza estos datos.
- **Ingeniería inversa**: Desciframos el flujo de la aplicación para detectar rutas no documentadas, endpoints API, y cualquier funcionalidad accesible desde el cliente que pueda ser explotada.

## Recomendaciones 

A partir de los hallazgos recurrentes, sugerimos lo siguiente:

- Validar y sanear todas las entradas de usuario, incluso si AngularJS implementa protecciones por defecto.
- Evitar el uso innecesario de directivas que permiten la inserción de HTML dinámico, como `ng-bind-html`.
- Mantener siempre actualizada la versión de AngularJS y aplicar parches de seguridad.
- Auditar los permisos y el uso de servicios y factories, evitando exponer información sensible en el cliente.

## Conclusión

Desde nuestra experiencia, AngularJS puede ser seguro si se implementa correctamente, pero su flexibilidad y potencia pueden ser un arma de doble filo. Nuestro enfoque como pentesters y bug hunters es identificar dónde esa flexibilidad puede convertirse en una vulnerabilidad, ayudando a los equipos de desarrollo a comprender los riesgos y a fortalecer sus aplicaciones.

---
