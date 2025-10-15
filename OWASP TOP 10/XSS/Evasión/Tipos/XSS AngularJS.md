
---

# DOM XSS en AngularJS Expression con caracteres HTML codificados

## Contexto del laboratorio

Este laboratorio contiene una vulnerabilidad **DOM-based Cross-Site Scripting (XSS)** dentro de una **expresión AngularJS** que se ejecuta en la funcionalidad de búsqueda del sitio.

AngularJS es una biblioteca JavaScript que permite enlazar datos entre el HTML y el código JavaScript mediante expresiones. Cuando el documento contiene el atributo `ng-app`, AngularJS escanea su contenido buscando expresiones entre `{{ }}` que pueden ser evaluadas dinámicamente.

Este comportamiento es muy potente para aplicaciones legítimas, pero también puede ser explotado si los datos del usuario se insertan sin una sanitización adecuada, permitiendo la ejecución de código arbitrario en el navegador.

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression)

---

## Análisis de la vulnerabilidad

En este caso, el reflejo del parámetro de búsqueda se encuentra dentro de una **expresión AngularJS**, y los caracteres especiales como los **ángulos `<` y `>`** y las **comillas dobles `"`** están **codificados en HTML**.  
Esto significa que no podemos inyectar etiquetas HTML directamente, pero aún podemos aprovechar el motor de expresiones de AngularJS para ejecutar JavaScript.

Por ejemplo, si la aplicación refleja un valor del tipo:

```html
<div ng-app="">
  {{ searchTerm }}
</div>
```

y el valor de `searchTerm` proviene directamente de `location.search` sin sanitización, entonces cualquier expresión AngularJS inyectada por el atacante será evaluada por el framework.

---

## Cómo funciona la explotación

La clave está en comprender que **AngularJS evalúa expresiones JavaScript entre las llaves `{{ }}`**.  
Podemos usar el objeto global `constructor` del `Function` para crear una nueva función que ejecute código arbitrario, incluso si los caracteres `<` y `>` están codificados.

El payload más habitual para explotar este tipo de vulnerabilidades es:

```js
{{constructor.constructor('alert(1)')()}}
```

### Desglose del payload

1. `{{ ... }}` → Indica a AngularJS que debe evaluar el contenido como una expresión.
    
2. `constructor` → Hace referencia al constructor del objeto actual.
    
3. `constructor.constructor('alert(1)')` → Crea una nueva función equivalente a `new Function('alert(1)')`.
    
4. `()` → Ejecuta inmediatamente esa función, lanzando la alerta.
    

---

## Payload utilizado

```
{{constructor.constructor('alert(1)')()}}
```

Este payload aprovecha el hecho de que AngularJS **evalúa expresiones dentro del DOM**.  
Al no haber mecanismos de sanitización, la expresión se ejecuta directamente, mostrando un `alert(1)` como prueba de ejecución de código arbitrario.

---

## Resumen técnico

|Elemento|Descripción|
|---|---|
|**Tipo de vulnerabilidad**|DOM-based XSS|
|**Tecnología afectada**|AngularJS|
|**Mecanismo de inyección**|Expresión AngularJS (`{{ }}`)|
|**Método de explotación**|Ejecución de JavaScript a través de `constructor.constructor`|
|**Payload final**|`{{constructor.constructor('alert(1)')()}}`|
|**Evidencia de éxito**|Ejecución del `alert(1)`|

---
