
---
# Puppeteer

## ¿Qué es Puppeteer?

> Puppeteer es una biblioteca oficial de Google que ofrece una API de alto nivel para controlar Chromium o Chrome mediante DevTools Protocol. Nos permite abrir navegadores, navegar páginas, ejecutar código en el contexto del navegador, tomar capturas, interceptar peticiones, emular dispositivos y mucho más.

Nos interesa porque muchas vulnerabilidades web sólo se manifiestan en el navegador (por ejemplo, ejecución real de JavaScript, manipulación del DOM, comportamientos que dependen de carga asíncrona). Con Puppeteer podemos automatizar comprobaciones y PoC reproducibles.

---

## Instalación

Desde un proyecto Node.js:

```bash
npm init -y
npm i puppeteer
```

Esto instala Puppeteer y, por defecto, también descarga una versión compatible de Chromium. Si preferimos usar una instalación de Chrome existente, podemos instalar `puppeteer-core` y configurar `executablePath`.

---

## Uso básico

### 1. Lanzar un navegador y abrir una página

```javascript
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto('https://example.com', { waitUntil: 'networkidle2' });
  await browser.close();
})();
```

- `headless: true` ejecuta Chromium sin interfaz gráfica. Para depuración podemos usar `headless: false`.
    
- `waitUntil: 'networkidle2'` espera a que no haya más de 2 conexiones de red pendientes — útil para páginas con recursos asíncronos.
    

---

### 2. Ejecutar código en el contexto de la página

```javascript
// Obtener el título de la página
const title = await page.evaluate(() => document.title);

// Ejecutar un script que devuelva una variable global
const result = await page.evaluate(() => {
  window._marker = 'OK';
  return window._marker;
});
```

`page.evaluate()` permite ejecutar funciones dentro del DOM, como si escribiéramos en la consola DevTools.

---

### 3. Rellenar formularios y clicar elementos

```javascript
await page.type('#username', 'admin');
await page.type('#password', 'password123');
await page.click('button[type=submit]');
await page.waitForNavigation();
```

Esto es útil para flujos que requieren autenticación o interacción previa a la comprobación.

---

### 4. Capturas y HTML

```javascript
await page.screenshot({ path: 'result.png', fullPage: true });
const html = await page.content(); // HTML generado por el navegador
```

Guardar HTML y capturas facilita la evidencia en un informe.

---

## Funcionalidades útiles para pentesting

- **Detectar ejecución de payloads XSS**: inyectar un payload que cree una variable global y comprobarla con `page.evaluate()` (como en nuestro PoC).
    
- **Automatizar ataques en workflows complejos**: login, navegación, envío de formularios, etc.
    
- **Bypass de medidas simples de protección**: emular cabeceras, cookies, User-Agent, geolocalización, tamaño de viewport.
    
- **Interceptación de peticiones**: modificar solicitudes/respuestas o capturar requests para análisis con `page.setRequestInterception(true)`.
    
- **Pruebas con múltiples contextos y navegadores**: ejecutar en modo visible para depuración o headless para integración continua.
    

---

## Ejemplos prácticos avanzados

### Interceptar y modificar solicitudes

```javascript
await page.setRequestInterception(true);
page.on('request', req => {
  if (req.url().includes('analytics')) {
    return req.abort(); // bloquear requests innecesarios
  }
  const overrides = {
    headers: Object.assign({}, req.headers(), { 'X-Bypass': 'PoC' })
  };
  req.continue(overrides);
});
```

### Emular cabeceras y User-Agent

```javascript
await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) MyPoC/1.0');
await page.setExtraHTTPHeaders({ 'X-From-Tool': 'poc' });
```

### Esperas y sincronización

- `page.waitForSelector(selector)` espera a que un elemento aparezca.
    
- `page.waitForTimeout(ms)` espera un tiempo fijo.
    
- `page.waitForResponse(predicate)` espera una respuesta que cumpla cierta condición.
    

Usar las esperas adecuadas evita falsos negativos en páginas con carga dinámica.

---

## Manejo de Content Security Policy y protecciones

- Puppeteer no elude CSP por sí solo. Si la página define CSP que bloquea `eval` o inline scripts, la ejecución de payloads inline puede fallar.
    
- Podemos inspeccionar cabeceras CSP usando `res.headers['content-security-policy']` (si usamos interceptores o fetch con `axios`) y adaptar la técnica.
    
- Existen plugins comunitarios (por ejemplo `puppeteer-extra-plugin-stealth`) que ayudan a evitar detección de automatización; mencionamos esto por su existencia, pero evaluamos su uso según el engagement y legalidad.
    

---

## Limitaciones y consideraciones prácticas

- Descargar Chromium aumenta el tamaño del `node_modules`; para entornos CI podemos usar `puppeteer-core` y apuntar a un Chrome ya presente.
    
- El comportamiento puede variar entre versiones de Chromium y navegadores reales; validar manualmente los hallazgos.
    
- Automatizar muchas pruebas simultáneas consume recursos (CPU/RAM). Gestionar el número de instancias y cerrar navegadores correctamente.
    

---

## Buenas prácticas para pentesters

- Ejecutar en modo `headless: false` para depuración y luego `headless: true` para automatización.
    
- Limpiar datos sensibles en capturas/HTML antes de compartir.
    
- Respetar `rate-limits` y el _scope_ del engagement.
    
- Añadir `try/catch` y asegurar `browser.close()` en `finally` para evitar procesos huérfanos.
    

---

## Checklist de uso en un PoC

1. Definir payloads discretos (p. ej. `window._xss_test='OK'`).
    
2. Usar `page.goto()` con `waitUntil` apropiado.
    
3. Verificar ejecución con `page.evaluate()`.
    
4. Guardar evidencia: `page.screenshot()` y `page.content()` si se detecta ejecución.
    
5. Registrar resultado en JSON/CSV para el informe.
    

---

## Recursos y referencias rápidas

- Puppeteer GitHub: [https://github.com/puppeteer/puppeteer](https://github.com/puppeteer/puppeteer)
    
- Documentación: [https://pptr.dev/](https://pptr.dev/)
    

---
