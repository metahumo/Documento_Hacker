
---

# Sources modernos de DOM XSS

## Introducción

Cuando analizamos XSS basado en DOM, solemos pensar de forma casi automática en parámetros GET, formularios o inputs visibles. Sin embargo, en aplicaciones modernas existen **fuentes de datos alternativas** que pueden alimentar sinks peligrosos sin pasar por los canales clásicos.

En este documento ampliamos nuestro modelo mental para identificar **sources modernos de DOM XSS**, entendiendo source como cualquier origen de datos **controlable directa o indirectamente por el usuario** que puede acabar llegando a un sink inseguro.

---

## Recordatorio rápido: source vs sink

- **Source**: origen del dato controlable.
    
- **Sink**: punto donde ese dato se interpreta como HTML o JavaScript.
    

La vulnerabilidad aparece cuando:

```
Source controlable → ausencia de validación → Sink peligroso
```

El foco no está en el payload, sino en **el flujo de datos**.

---

## Sources clásicos (ya conocidos)

Estos son los que solemos detectar primero:

- Parámetros GET (`location.search`)
    
- Parámetros POST
    
- Campos de formularios
    
- Fragmentos de URL (`location.hash`)
    
- Cookies accesibles desde JS
    

Aunque siguen siendo relevantes, **no cubren la superficie real de ataque** en aplicaciones modernas.

---

## Sources modernos de DOM XSS

### 1. Web Messages (`postMessage`)

`window.postMessage()` permite enviar datos entre ventanas, iframes o popups, incluso entre orígenes distintos.

Ejemplo típico:

```js
window.addEventListener('message', function(e) {
    element.innerHTML = e.data;
});
```

Aquí:

- `e.data` es el **source**
    
- `innerHTML` es el **sink**
    

Si no se valida:

- origen (`e.origin`)
    
- contenido del mensaje
    

tenemos un DOM XSS explotable.

Este source es muy común en:

- anuncios
    
- widgets
    
- integraciones de terceros
    
- dashboards internos
    

---

### 2. localStorage / sessionStorage

Datos almacenados previamente por el usuario o por la aplicación:

```js
element.innerHTML = localStorage.getItem('theme');
```

Si el atacante puede escribir en storage (XSS previo, lógica insegura, importaciones), el valor se convierte en input persistente.

---

### 3. window.name

`window.name` persiste entre navegaciones y puede ser controlado:

```js
document.body.innerHTML = window.name;
```

Es un source olvidado y muy potente en flujos complejos.

---

### 4. document.referrer

Algunas aplicaciones insertan el referrer en el DOM:

```js
element.innerHTML = document.referrer;
```

Si el atacante controla la URL de origen, controla el contenido.

---

### 5. Mensajes de APIs internas

Datos devueltos por:

- `fetch()`
    
- `XMLHttpRequest`
    
- APIs internas JSON
    

que luego se insertan sin escape:

```js
fetch('/api/data').then(r => r.text()).then(d => el.innerHTML = d);
```

Si la API refleja datos controlables, el source es indirecto pero válido.

---

### 6. Atributos HTML dinámicos

Valores obtenidos de atributos:

```js
const value = element.getAttribute('data-content');
target.innerHTML = value;
```

Si el atacante puede influir en ese atributo, controla el source.

---

## Idea clave

No buscamos únicamente inputs visibles.

Buscamos **cualquier dato que pueda fluir hasta un sink peligroso**, aunque:

- venga de otra ventana
    
- venga de almacenamiento
    
- venga de un iframe
    
- venga de una API
    

El XSS moderno consiste en **mapear flujos**, no en tirar payloads a ciegas.

---

## Conclusión

Ampliar el concepto de source nos permite:

- detectar XSS donde otros no miran
    
- encadenar vulnerabilidades (clickjacking + DOM XSS)
    
- elevar impacto en bug bounty
    

Un sink inseguro siempre es grave.  
Pero un sink inseguro alimentado por un source moderno suele ser **crítico**.

---