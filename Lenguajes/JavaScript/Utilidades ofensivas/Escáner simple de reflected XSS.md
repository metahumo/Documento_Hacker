
---

# Escáner simple de reflected XSS con Node.js (`axios`)

## Para qué sirve esta herramienta

Esta pequeña utilidad nos ayuda a **detectar reflejos simples** de payloads en parámetros de URL. Es una comprobación rápida: construye una URL inyectando un payload en un parámetro, solicita la página y busca si el payload aparece en el cuerpo de la respuesta. Si aparece, puede indicar un posible **reflected XSS** (aunque no garantiza ejecución).

---

## Código completo (`xss_check.js`)

Guardamos esto en un fichero llamado `xss_check.js`. Requiere Node.js y la librería `axios` (`npm i axios`).

```javascript
// xss_check.js
// Uso: node xss_check.js <url> <param> <payload>
// Ejemplo: node xss_check.js "https://example.com/search" "q" "<script>alert(1)</script>"

const axios = require('axios');

async function testReflected(urlBase, param, payload, timeout = 8000) {
  try {
    // Construimos URL con el payload en el query param
    const url = new URL(urlBase);
    url.searchParams.set(param, payload);

    const finalUrl = url.toString();
    console.log(`[+] Testing: ${finalUrl}`);

    // Petición GET
    const res = await axios.get(finalUrl, { timeout });

    const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

    // Búsqueda simple del payload en la respuesta HTML/JSON
    if (body.includes(payload)) {
      console.log(`[!] Possible reflection FOUND for param "${param}" at: ${finalUrl}`);
      return { url: finalUrl, reflected: true, status: res.status };
    } else {
      console.log(`[-] No reflection detected for param "${param}" (status ${res.status})`);
      return { url: finalUrl, reflected: false, status: res.status };
    }
  } catch (err) {
    // Manejo básico de errores (timeout, conexión, 4xx/5xx)
    console.error(`[x] Error testing ${urlBase} with param "${param}": ${err.message}`);
    return { url: urlBase, reflected: false, error: err.message };
  }
}

// Entrada por línea de comandos
(async () => {
  const [,, urlBase, param, payload] = process.argv;

  if (!urlBase || !param || !payload) {
    console.log('Usage: node xss_check.js <urlBase> <param> <payload>');
    console.log('Example: node xss_check.js "https://example.com/search" "q" "<script>alert(1)</script>"');
    process.exit(1);
  }

  // Llamada principal
  const result = await testReflected(urlBase, param, payload);
})();
```

---

## Explicación de código

### 1) Cabecera y dependencias

```javascript
const axios = require('axios');
```

- Importamos `axios` para hacer peticiones HTTP. Es simple y ampliamente usado en Node.js.
    

---

### 2) Función principal `testReflected`

```javascript
async function testReflected(urlBase, param, payload, timeout = 8000) { ... }
```

- Es `async` porque realizamos peticiones `await axios.get(...)`.
    
- Parámetros:
    
    - `urlBase`: la URL base (ej. `https://example.com/search`). Se añade por argumento al ejecutar el script.
        
    - `param`: el nombre del parámetro donde inyectaremos (ej. `q`).
        
    - `payload`: el payload que queremos buscar (ej. `<script>alert(1)</script>`).
        
    - `timeout`: tiempo máximo para la petición (opc.).
        

---

### 3) Construcción segura de la URL

```javascript
const url = new URL(urlBase);
url.searchParams.set(param, payload);
const finalUrl = url.toString();
console.log(`[+] Testing: ${finalUrl}`);
```

- `new URL(urlBase)` nos facilita añadir parámetros y garantiza codificación correcta.
    
- `searchParams.set()` añade o reemplaza el parámetro con nuestro payload.
    
- Mostramos en consola la URL que vamos a probar (útil para auditoría y reproducibilidad).
    

---

### 4) Petición HTTP y lectura del cuerpo

```javascript
const res = await axios.get(finalUrl, { timeout });
const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
```

- Hacemos `GET`. 
    
- `res.data` puede ser HTML o JSON; lo normalizamos a `string` para buscar el payload.
    

---

### 5) Comprobación de reflexión (búsqueda simple)

```javascript
if (body.includes(payload)) {
  console.log(`[!] Possible reflection FOUND ...`);
  return { url: finalUrl, reflected: true, status: res.status };
} else {
  console.log(`[-] No reflection detected ...`);
  return { url: finalUrl, reflected: false, status: res.status };
}
```

- Si el cuerpo contiene exactamente el payload, marcamos como posible reflejo.
    
- **IMPORTANTE:** esto solo detecta **reflejo textual**, no ejecución. Muchos filtros/encoding pueden falsear resultados.
    

---

### 6) Manejo de errores

```javascript
} catch (err) {
  console.error(`[x] Error testing ${urlBase} with param "${param}": ${err.message}`);
  return { url: urlBase, reflected: false, error: err.message };
}
```

- Capturamos timeouts, rechazos TLS, respuestas inesperadas, etc., y devolvemos un objeto con `error`.
    

---

### 7) Entrada desde la CLI y ejecución

```javascript
const [,, urlBase, param, payload] = process.argv;
if (!urlBase || !param || !payload) { ... }
const result = await testReflected(urlBase, param, payload);
```

- Permitimos ejecutar por línea de comandos: `node xss_check.js <urlBase> <param> <payload>`.
    

---

## Ejemplo de ejecución y salida

Comando:

```bash
node xss_check.js "https://example.com/search" "q" "<script>alert(1)</script>"
```

Salida posible (dos escenarios):

1. **Reflejo XSS detectado**:
    

```
[+] Testing: https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
[!] Possible reflection FOUND for param "q" at: https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

2. **No detectado**:
    

```
[+] Testing: https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
[-] No reflection detected for param "q" (status 200)
```

3. **Error de conexión / timeout**:
    

```
[+] Testing: https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
[x] Error testing https://example.com/search with param "q": timeout of 8000ms exceeded
```

---

## Análisis de la información obtenida y utilidad práctica

- **Si encontramos reflexión textual** (`body.includes(payload)`):
    
    - Indica que el servidor devuelve la entrada del parámetro sin quitarla o codificarla totalmente.
        
    - **Siguiente paso** (no realizado por el script): intentar comprobar si el reflejo XSS se **ejecuta** en navegador (ej. con Puppeteer) — porque solo la presencia no implica ejecución (puede estar escapada como `&lt;script&gt;`).
        
    - También debemos analizar contexto: ¿se refleja dentro de HTML, atributo, `<script>`, URL? El contexto define técnicas de explotación y payloads.
        
- **Si no hay reflejo**:
    
    - Podría significar que el servidor escapa/sanitiza, filtra o usa parámetros server-side sin reflejarlos. También puede que el payload se refleje en partes que `axios`/server no devuelve (por ejemplo, solo en respuestas dinámicas client-side).
        
- **Errores/Time-outs**:
    
    - Indicativos de WAF, protecciones, o problemas de conectividad. Útiles para decidir retocar timing, proxies, o técnicas de evasión.
        

---

## Menciones rápidas — siguientes pasos 

- Iterar una **lista de payloads** y una lista de **parámetros** automáticamente.
    
- Normalizar/limpiar `body` para evitar falsos positivos (strip HTML o decodificar entidades).
    
- Intentar **ejecución real** con un navegador automatizado (Puppeteer / Playwright).
    
- Integrar logging/CSV/JSON de resultados para reporting.
    
- Añadir _rate limiting_ / delays y respeto a robots / políticas para evitar DoS o detección.
    
- Usar proxies (Burp) para análisis manual más profundo.
       


---
