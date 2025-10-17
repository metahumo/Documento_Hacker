
---

# Comprobador de ejecución de payload con Puppeteer

## ¿Para qué sirve esta herramienta?

Esta herramienta automatiza un navegador (Chromium) usando **Puppeteer** para:

- Navegar a una URL que contiene nuestro payload.
    
- Esperar a que la página cargue.
    
- Verificar si el payload se ejecutó realmente en el contexto de la página (por ejemplo, comprobando la existencia de una variable global creada por el payload).  
    Esto nos permite diferenciar entre **reflejo textual** (aparece en la respuesta) y **ejecución real**, que es lo que realmente importa para vulnerabilidades XSS explotables.
    

---

## Requisitos

- Node.js instalado.
    
- Instalar Puppeteer en el proyecto:
    

```bash
npm init -y
npm i puppeteer
```

---

## Código completo (`puppeteer_xss.js`)

Guardar en `puppeteer_xss.js`.

```javascript
// puppeteer_xss.js
// Uso:
// node puppeteer_xss.js "<urlBase>" "<param>" "<payload>"
// Ejemplo:
// node puppeteer_xss.js "https://example.com/search" "q" "<script>window._xss_test='XSS_OK'</script>"

const puppeteer = require('puppeteer');

async function testExecution(urlBase, param, payload, options = {}) {
  const {
    headless = true,
    timeout = 12000,
    waitUntil = 'networkidle2',
    screenshotOnSuccess = false,
    screenshotPath = 'xss_success.png'
  } = options;

  // Construimos URL con query param codificado
  const urlObj = new URL(urlBase);
  urlObj.searchParams.set(param, payload);
  const targetUrl = urlObj.toString();

  console.log(`[+] Opening browser (headless=${headless}) and navigating to: ${targetUrl}`);

  const browser = await puppeteer.launch({ headless });
  const page = await browser.newPage();

  try {
    // Opcional: ajustar User-Agent o cabeceras si queremos simular un navegador real
    await page.setDefaultNavigationTimeout(timeout);

    // Ir a la URL con el payload
    await page.goto(targetUrl, { waitUntil, timeout });

    // Pequeña espera adicional por si hay JS dinámico
    await page.waitForTimeout(500);

    // Comprobamos si la variable global creada por el payload existe.
    // El payload de ejemplo debe crear window._xss_test = 'XSS_OK'
    const executed = await page.evaluate(() => {
      try {
        return typeof window._xss_test !== 'undefined' ? window._xss_test : null;
      } catch (e) {
        return null;
      }
    });

    if (executed) {
      console.log(`[!] Payload executed in page context. Detected value: ${executed}`);
      if (screenshotOnSuccess) {
        await page.screenshot({ path: screenshotPath, fullPage: true });
        console.log(`[+] Screenshot saved to ${screenshotPath}`);
      }
      await browser.close();
      return { url: targetUrl, executed: true, value: executed };
    } else {
      console.log('[-] Payload not executed or was neutralized/sanitized by the page.');
      await browser.close();
      return { url: targetUrl, executed: false };
    }

  } catch (err) {
    console.error(`[x] Error while testing ${targetUrl}: ${err.message}`);
    await browser.close();
    return { url: targetUrl, executed: false, error: err.message };
  }
}

// Entrypoint CLI
(async () => {
  const [,, urlBase, param, payload] = process.argv;
  if (!urlBase || !param || !payload) {
    console.log('Usage: node puppeteer_xss.js "<urlBase>" "<param>" "<payload>"');
    process.exit(1);
  }

  // Ejemplo de opciones: ver en modo no-headless y guardar screenshot si se ejecuta
  const options = {
    headless: true,
    screenshotOnSuccess: false
  };

  const result = await testExecution(urlBase, param, payload, options);
  console.log('Result:', result);
})();
```

---

## Desglose del script (fracciones y explicación)

### 1) Import y firma de la función

```javascript
const puppeteer = require('puppeteer');

async function testExecution(urlBase, param, payload, options = {}) { ... }
```

- Importamos Puppeteer.
    
- `testExecution` es asíncrona y recibe la URL base, el nombre del parámetro, el payload y opciones configurables.
    

---

### 2) Opciones por defecto

```javascript
const {
  headless = true,
  timeout = 12000,
  waitUntil = 'networkidle2',
  screenshotOnSuccess = false,
  screenshotPath = 'xss_success.png'
} = options;
```

- Permitimos configurar ejecución headless/visible, timeouts y captura de pantalla al detectar ejecución.
    

---

### 3) Construcción de la URL con payload

```javascript
const urlObj = new URL(urlBase);
urlObj.searchParams.set(param, payload);
const targetUrl = urlObj.toString();
```

- Garantizamos codificación correcta del parámetro usando `URL` y `searchParams.set()`.
    

---

### 4) Lanzamiento de navegador y navegación

```javascript
const browser = await puppeteer.launch({ headless });
const page = await browser.newPage();
await page.setDefaultNavigationTimeout(timeout);
await page.goto(targetUrl, { waitUntil, timeout });
await page.waitForTimeout(500);
```

- Abrimos el navegador.
    
- Navegamos al `targetUrl` y esperamos hasta que la red esté tranquila (`networkidle2`), lo que ayuda con páginas que cargan recursos asíncronos.
    

---

### 5) Comprobación de ejecución del payload

```javascript
const executed = await page.evaluate(() => {
  try {
    return typeof window._xss_test !== 'undefined' ? window._xss_test : null;
  } catch (e) {
    return null;
  }
});
```

- `page.evaluate` ejecuta código dentro del contexto de la página (como si lo ejecutásemos en la consola devtools).
    
- El payload de ejemplo debe crear `window._xss_test = 'XSS_OK'` para que lo detectemos. Si existe, consideramos que _se ejecutó_.
    

---

### 6) Resultado y cierre

```javascript
if (executed) {
  // guardamos screenshot opcional, cerramos y devolvemos resultado positivo
} else {
  // cerramos y devolvemos que no se ejecutó
}
```

- Siempre cerramos el navegador para liberar recursos.
    
- Devolvemos un objeto con `executed: true/false` y detalles.
    

---

### 7) CLI entrypoint

```javascript
const [,, urlBase, param, payload] = process.argv;
```

- Permite ejecutar desde línea de comandos:
    

```
node puppeteer_xss.js "<urlBase>" "<param>" "<payload>"
```

---

## Payload recomendado para pruebas (ejemplo)

Usaremos un payload que, si se ejecuta, deje una señal clara en `window`:

```html
<script>window._xss_test = 'XSS_OK'</script>
```

Este payload **no** intenta causar alert ruidoso; es una bandera discreta para detección automática.

---

## Ejemplo de ejecución y salida

Comando:

```bash
node puppeteer_xss.js "https://example.com/search" "q" "<script>window._xss_test='XSS_OK'</script>"
```

Salidas posibles:

1. **Ejecución detectada**
    

```
[+] Opening browser (headless=true) and navigating to: https://example.com/search?q=%3Cscript%3Ewindow._xss_test%3D'XSS_OK'%3C%2Fscript%3E
[!] Payload executed in page context. Detected value: XSS_OK
Result: { url: 'https://example.com/search?q=...', executed: true, value: 'XSS_OK' }
```

2. **No ejecutado (sanitizado/neutralizado)**
    

```
[+] Opening browser (headless=true) and navigating to: https://example.com/search?q=%3Cscript%3Ewindow._xss_test%3D'XSS_OK'%3C%2Fscript%3E
[-] Payload not executed or was neutralized/sanitized by the page.
Result: { url: 'https://example.com/search?q=...', executed: false }
```

3. **Error / timeout**
    

```
[+] Opening browser (headless=true) and navigating to: https://example.com/search?q=...
[x] Error while testing https://example.com/search?q=...: Navigation timeout of 12000 ms exceeded
Result: { url: 'https://example.com/search', executed: false, error: 'Navigation timeout...' }
```

---

## Análisis de la información obtenida y utilidad práctica

- **Caso ejecutado (`executed: true`)**
    
    - Confirmación de que la inyección no solo se refleja sino que **llega a ejecutarse** en el contexto de la página. Es una señal fuerte de XSS explotable.
        
    - Utilidad: Priorizar este hallazgo para explotación/PoC más completa y reporte. Genera evidencia sólida para el informe (URL, payload, captura de pantalla opcional).
        
    - Riesgos/consideraciones: revisar contexto exacto (dónde se ejecuta, si es persistente o solo reflected, qué cookies/sesiones pueden verse afectadas).
        
- **Caso no ejecutado (`executed: false`)**
    
    - Indica que la entrada fue reflejada pero neutralizada (escaped), o que no se reflejó, o que la ejecución está protegida por CSP u otras medidas.
        
    - Utilidad: nos indica que debemos probar otros payloads/contextos (atributos, eventos, encodings, métodos POST) o emplear técnicas de bypass (si es permitido).
        
    - No asumir que está 100% seguro: investigar contexto de salida (atributo, HTML, script, url) y CSP.
        
- **Errores/timeouts**
    
    - Pueden indicar protecciones (WAF, rate-limiting), problemas de conectividad o la necesidad de ajustar `waitUntil`/timeouts. Útiles para afinar la metodología.
        

---

## Menciones rápidas — siguientes pasos (solo mencionarlos)

- Probar una **lista de payloads** más amplia y específicos por contexto (atributos, eventos, URL, etc.).
    
- Automatizar iteración sobre **varios parámetros** y **métodos HTTP** (GET/POST).
    
- Añadir lógica para detectar y parsear **Content Security Policy (CSP)**.
    
- Implementar **captura y almacenamiento** de evidencias (screenshots, HTML) para reporting.
    
- Integrar con un proxy (ej. Burp) para inspección manual y manipulación de requests.
    
- Respectar _rate limits_ y evitar pruebas de DoS; siempre dentro de permisos.
    

---

## Consejos prácticos y seguridad al ejecutar

- Para depurar, usa `headless: false` y verás el navegador.
    
- Evita payloads ruidosos en entornos reales; usa técnicas discretas como la bandera `window._xss_test`.
    
- Limpia cualquier dato sensible en las capturas y en los logs antes de compartir.
    
- Añade delays entre pruebas y no escales la herramienta sin autorización.
    

---

Si quieres que lo entregue como un **.md** listo para guardar (con primera persona del plural y sin iconos, como me pediste antes cuando dijiste ".md"), dime “pásame .md” y te lo dejo en ese formato.

¿Lo quieres tal cual, o quieres que:

- lo haga **headless:false** por defecto para ver la ejecución,
    
- o que añada la opción de guardar automáticamente el HTML completo al detectar ejecución,
    
- o que incluya un pequeño conjunto de payloads y haga iteración básica?
    

Dime “ok” si está listo y hemos acabado con este PoC, o pide la modificación que prefieras.