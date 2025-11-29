
---

# Escape de sandbox AngularJS sin cadenas

En este documento vemos una vulnerabilidad de **XSS reflejado** en una aplicación que usa AngularJS con su _sandbox_ reforzado. La inyección se sitúa dentro de una expresión de Angular, pero el entorno se ha configurado para bloquear explícitamente el uso de cadenas literales y operaciones tipo `eval`. Aun así, conseguimos ejecutar código construyendo las cadenas necesarias **sin usar comillas** ni funciones evaluadoras directas.

La técnica aprovecha propiedades y métodos nativos de JavaScript (como `constructor`, `toString()` y `fromCharCode`) y una pequeña interferencia en prototipos para formar la cadena objetivo indirectamente. Con esto, se genera la secuencia de caracteres `x=alert(1)` en tiempo de ejecución y se utiliza en un contexto donde Angular normalmente rechazará cadenas o `eval`. El laboratorio demuestra que restricciones aparentemente fuertes en el sandbox pueden burlarse mediante manipulación de comportamiento de objetos y construcción indirecta de cadenas.

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings)

---

## ¿Qué es sandbox en AngularJS y para qué sirve?

El **sandbox** de AngularJS es un conjunto de restricciones que impone el framework cuando evalúa expresiones (por ejemplo, dentro de plantillas). Su objetivo es evitar que una plantilla ejecute funciones peligrosas o acceda a APIs globales que puedan provocar XSS u otros comportamientos no deseados. Para ello, Angular filtra identificadores, prohíbe ciertas propiedades y evita la evaluación dinámica desde cadenas. El laboratorio muestra cómo, aun con esas defensas, se puede encontrar una vía de ejecución creativa aprovechando mecanismos propios de JavaScript.

**Nota sobre el estado actual de AngularJS**

AngularJS dejó de recibir soporte oficial el **31 de diciembre de 2021**, fecha en la que Google finalizó definitivamente su _Long Term Support (LTS)_. Desde entonces, el framework no recibe parches de seguridad, actualizaciones ni mantenimiento de su equipo original.

A pesar de ello, sigue siendo **muy común** encontrar AngularJS en producción, especialmente en:

- **Aplicaciones web antiguas** que no han migrado a Angular moderno (Angular 2+), React o Vue.
    
- **Portales corporativos** cuyo ciclo de actualización es lento o dependen de código heredado.
    
- **Dashboards internos**, paneles administrativos y herramientas legacy.
    
- **Programas de bug bounty**, donde aparece con frecuencia en aplicaciones grandes, maduras o multicapa que mantienen componentes antiguos mezclados con tecnologías modernas.
    

Esta presencia continua hace que el estudio de vulnerabilidades en AngularJS —incluidos escapes del sandbox, bypasses de sanitización y técnicas de template injection— siga siendo **relevante para pentesters, analistas de seguridad y cazadores de bugs**. Aunque el framework esté oficialmente descontinuado, su exposición en servicios reales convierte este tipo de laboratorios en conocimientos prácticos que aún tienen valor en auditorías y pruebas autorizadas.

---

## Contexto del laboratorio

- Aplicación vulnerable: página que evalúa expresiones Angular en el cliente (por ejemplo, `{{ expression }}`) y aplica sanitización/sandbox para bloquear cadenas y `eval`.
    
- Restricciones observadas:
    
    - Las literales de cadena (`'...'` o `"..."`) son bloqueadas o deshabilitadas por el filtro interno.
        
    - El uso de funciones evaluadoras directas está restringido.
        
    - Sin embargo, los objetos y sus prototipos conservan métodos nativos accesibles (por ejemplo, `toString`, `constructor`, `fromCharCode`).
        
- Objetivo: conseguir ejecutar una acción visible de prueba (p.ej. `alert(1)`) sin usar comillas ni `eval` directo.
    

---

## Idea del ataque

1. Construir la cadena objetivo (por ejemplo `x=alert(1)`) **sin** usar comillas.
    
2. Para eso, generar los caracteres a partir de sus códigos numéricos con `String.fromCharCode(...)`.
    
3. Conseguir acceso a `String` o `Function` sin recurrir a literales: aprovechar `constructor` y `toString()` sobre objetos nativos accesibles desde el contexto Angular.
    
4. Si es necesario, modificar (temporalmente y de forma local) comportamiento en prototipos (por ejemplo, sobrescribir un método de `String.prototype`) para que una operación permitida devuelva los fragmentos deseados.
    
5. Ensamblar esos fragmentos y provocar su evaluación en el contexto de la plantilla (p.ej. pasando la expresión generada a un filtro como `orderBy` u otro que acepte una expresión a evaluar).
    

## Función vulnerable

La aplicación utiliza una función muy simple que, sin embargo, introduce un riesgo serio: está evaluando una **expresión controlada por el usuario** mediante `$parse`. Este servicio de AngularJS transforma texto en una **expresión ejecutable**, y cuando la entrada no está totalmente controlada permite que un atacante influya directamente en lo que se evalúa.

```javascript
angular.module('labApp', []).controller('vulnCtrl',function($scope, $parse) {
    $scope.query = {};
    var key = 'search';
    $scope.query[key] = 'test';
    $scope.value = $parse(key)($scope.query);
});
```

Lo relevante es el uso de:

```javascript
$parse(key)($scope.query);
```

- Primero, `$parse(key)` interpreta **el contenido de la variable `key` como una expresión AngularJS**, no como texto estático.
    
- Después, la evalúa con el contexto `$scope.query`.
    

En condiciones normales esto se usa para leer propiedades dinámicas. Pero, si el valor de `key` o del campo que llega al template se puede manipular desde fuera, se abre la puerta a **inyectar una expresión AngularJS arbitraria**.

Aunque el sandbox intenta limitar operaciones peligrosas (cadenas literales, `eval`, accesos a objetos globales), sigue siendo posible construir rutas hacia métodos nativos de JavaScript (`constructor`, `fromCharCode`, etc.) y forzar la ejecución de código.

En este laboratorio, esa combinación —evaluación dinámica + restricciones incompletas del sandbox— es justo lo que permite escapar y ejecutar un payload como `alert(1)` sin usar comillas.

**¿Qué es un módulo en AngularJS?**

> Un módulo en AngularJS es un contenedor de código que agrupa componentes relacionados como controladores, servicios y directivas para organizar la aplicación en partes más manejables. Sirve para dividir la aplicación en bloques lógicos, facilitando el desarrollo, mantenimiento y reutilización del código. En versiones más recientes de Angular, un módulo se define con el decorador `@NgModule`, que configura una clase para agrupar componentes, directivas, pipes y servicios, y para definir dependencias con otros módulos

**¿Qué es un controlador en AngularJS?**

> Un controlador en AngularJS es una clase de JavaScript que define el comportamiento de una parte de la vista, actuando como un "puente" entre la lógica de la aplicación y la interfaz de usuario. Su función principal es procesar datos, manejar eventos de la interfaz de usuario y exponer datos y funciones al `scope` para que la vista pueda mostrarlos y interactuar con ellos. 

Funciones principales

- **Gestión de lógica:** Mantiene la lógica de negocio y la funcionalidad de una sección de la aplicación, separándola del código HTML.
- **Manejo de datos:** Obtiene datos de la vista, los procesa y los entrega de vuelta a la vista que se muestra al usuario.
- **Respuesta a eventos:** Responde a las interacciones del usuario en la interfaz, permitiendo modificar la vista en tiempo real.
- **Conexión con la vista:** Utiliza la directiva *ng-controller* para asociarse con una parte del DOM (la vista). El *$scope* (o el alias `controller as`) actúa como el vínculo entre el controlador y su vista asociada

---

## Fase de testeo

Antes de intentar un escape completo del sandbox, comprobamos si la aplicación **evalúa expresiones AngularJS procedentes de parámetros de la URL**. Para ello modificamos el valor que se usa como clave (`key`) y observamos si se ejecutan operaciones aritméticas simples.

Ejemplo de prueba:

```
search=testing&2+2
```

Como el signo `+` es un carácter reservado en URLs, lo codificamos como `%2b`, quedando:

```url
web-security-academy.net/?search=testing&2%2b2
```

### ¿Qué estamos verificando aquí?

- Que Angular está interpretando la parte `2+2` como una **expresión**, no como texto literal.
    
- Si la aplicación devuelve como resultado el valor calculado, significa que **el sandbox está evaluando código procedente de parámetros externos**.
    

### Resultado esperado

```html
# 0 search results for 4
```

El `4` confirma que Angular ha interpretado y evaluado la expresión `2+2`. Esto nos indica que hay una ruta realista hacia una ejecución arbitraria de código dentro del template.

---

## Payload que resuelve el laboratorio

> Nota pedagógica: aquí mostramos cómo se **construye** la cadena objetivo sin usar comillas, aprovechando `fromCharCode`. Esto nos permite generar `x=alert(1)` incluso cuando el sandbox bloquea literales.

El payload aprovecha dos ideas clave:

1. **Modificar temporalmente un método del prototipo** (`charAt`) para que devuelva algo distinto a lo habitual y así evitar restricciones del sandbox.
    
2. **Construir la cadena peligrosa** con `fromCharCode`, accediendo a ella indirectamente mediante `toString().constructor`.
    

### Payload explicado

```
toString().constructor.prototype.charAt=[].join; 
[1,2]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
```

La parte final genera dinámicamente la cadena:

```js
"x=alert(1)"
```

Codificamos en URL el signo `=` (que debe ir como `%3d`):

```url
web-security-academy.net/?search=testing&toString().constructor.prototype.charAt%3d[].join; [1,2]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
```

### ¿Qué ocurre ahí dentro?

- `toString().constructor` → accede implícitamente al constructor de `String`, evitando usar la palabra “String” directamente.
    
- `.fromCharCode(120,61,97,108,101,114,116,40,49,41)` → genera los caracteres que forman `x=alert(1)` sin escribir ninguna cadena literal.
    
- `[1,2]|orderBy:EXPRESIÓN` → `orderBy` evalúa su argumento como expresión Angular, lo que ejecuta finalmente `x=alert(1)`.
    

### Notas técnicas importantes

- En este tipo de laboratorios es normal modificar un método del prototipo (como `charAt`) para evitar controles del sandbox:  
    `toString().constructor.prototype.charAt = [].join`
    
- Si el sandbox bloquea el uso directo de `String.fromCharCode`, accedemos a él a través de rutas alternativas como:
    
    - `{}.toString().constructor`
        
    - `[].constructor`
        
	Esto evita los filtros basados en identificadores literales.
    

Podemos comprobar una lista de cheat-sheet para ver los múltiples payload que son frecuentes antes un Sandbox de AngularJS: [Portswigger Cheat-Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

---

## Paso a paso (resumen)

1. Reconocer qué objetos y métodos están permitidos por el sandbox (por ejemplo, arrays `[]`, objetos `{}`, `toString`).
    
2. Localizar una cadena de llamadas que permita llegar a `String` o a `Function` sin usar cadenas. Ejemplos típicos:
    
    - `[].constructor` → `Array` constructor
        
    - `{}.toString().constructor` → puede dar acceso a `String` constructor en algunos contextos
        
3. Usar `fromCharCode` (vía la referencia hallada) para construir los caracteres uno a uno o en bloque a partir de sus códigos.
    
4. (Opcional y con precaución) ajustar temporalmente un método del prototipo para devolver fragmentos o transformar índices en caracteres si eso facilita esquivar comprobaciones del sandbox.
    
5. Pasar la cadena resultante al punto de evaluación (p. ej. un filtro que acepte una expresión) para que Angular la evalúe y el payload se ejecute.
    
6. Comprobar resultado (p. ej. `alert(1)`) y documentar la evidencia.
    

---

## Por qué funciona

- AngularJS protege contra inyección directa de cadenas y evals buscando patrones comunes (literales entre comillas, uso explícito de `eval`, `Function(...)`, etc.). Sin embargo, **no** puede bloquear todas las rutas legítimas que JavaScript ofrece para construir o obtener referencias a constructores y métodos.
    
- JavaScript es dinámico: cualquier objeto tiene una `constructor` y métodos como `toString`. Al combinar estas propiedades podemos alcanzar funciones como `String.fromCharCode` o `Function` sin escribir sus nombres literalmente.
    
- Las defensas típicas del sandbox suelen filtrar patrones textuales; la construcción dinámica a partir de números (códigos ASCII) y la manipulación de prototipos evita esas reglas simples.
    
- Si además el atacante consigue que un método permitido devuelva código o una referencia evaluable, Angular puede acabar ejecutándolo en su propia evaluación de expresiones.
    

---

## Notas y pequeños gotchas

- Algunos entornos parchean las rutas más obvias (`[].constructor`, `{}.toString`) o eliminan `fromCharCode` de los objetos accesibles — siempre comprobar qué está realmente disponible en el contexto de la aplicación objetivo.
    
- Modificar prototipos (`String.prototype.* = ...`) puede ser detectado por heurísticas de seguridad o romper otras funcionalidades; en un laboratorio suele ser viable, en producción es más ruidoso.
    
- No todos los filtros u operaciones en Angular evalúan expresiones del mismo modo. `orderBy` es útil en muchos labs porque acepta expresiones, pero el comportamiento exacto depende de la versión de Angular y de parches aplicados.
    
- El payload puede requerir encodeo/escape adicional si la plantilla procesa previamente entradas (p. ej. `ng-bind` vs `ng-bind-html`).
    
- Herramientas automáticas de WAF/SIEM pueden detectar patrones inusuales (p.ej. uso intensivo de `fromCharCode`), así que el enfoque puede necesitar variaciones para eludir detección (esto entra en el terreno de evasión y debe realizarse **solo** con autorización).
    

---

## Mitigaciones (cómo debería corregirse)

1. Evitar evaluar expresiones procedentes de datos no confiables en el cliente. Si no es estrictamente necesario, no permitir que datos externos se interpreten como expresiones Angular.
    
2. Usar versiones de frameworks que incluyan parches de seguridad más recientes y aplicar hardening del sandbox (parcheo de rutas comunes de escape).
    
3. Restringir el acceso al prototipo y a constructores desde el contexto de plantillas (si es posible), por ejemplo mediante una política que limite las propiedades accesibles en las expresiones.
    
4. Implementar Content Security Policy (CSP) en modo `script-src 'self'` y otras directivas que reduzcan el impacto de ejecución de scripts inyectados.
    
5. Saneamiento/validación en servidor de las entradas que serán renderizadas en plantillas, reduciendo la superficie que llega al cliente.
    
6. Monitorizar y alertar sobre patrones de entrada inusuales (por ejemplo, uso repetido de llamadas numéricas a `fromCharCode` o cadenas largas formadas por secuencias numéricas).
    

---

## Detección y respuesta (blue team)

- Monitorizar logs de cliente/servidor para entradas que contienen secuencias de números largas o patrones de `fromCharCode` y `constructor`.
    
- Instrumentar WAF/IDS para señales típicas de escape de sandbox: accesos a `constructor`, `toString`, `fromCharCode` desde parámetros que luego se evalúan.
    
- Revisar y alertar cuando se detecten sobrescrituras de prototipos (`String.prototype.*`, `Array.prototype.*`) en entornos donde no es esperado.
    
- Realizar análisis de comportamiento en la UI: si aparecen `alert`/`console`/peticiones inesperadas desde páginas públicas, investigar origen de la plantilla y la entrada.
    
- Respuesta: aplicar bloqueo temporal del input fuente, forzar logout/rotación de sesiones si se detecta ejecución, y hacer un análisis forense del vector (capturar payloads, variables de contexto y versiones de Angular).
    

---

## Ética y uso responsable

Este contenido es estrictamente educativo. Debemos probar técnicas de explotación **solo** en entornos controlados (laboratorios, máquinas virtuales propias, o con autorización expresa del propietario del sistema). El uso no autorizado de estas técnicas para atacar aplicaciones ajenas es ilegal y dañino. Si hallas una vulnerabilidad en software de terceros, sigue un proceso responsable: no explotar, documentar evidencia mínima, y reportar al responsable/bug bounty según sus políticas.

---

