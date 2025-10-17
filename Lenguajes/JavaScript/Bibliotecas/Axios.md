
---
# Axios

## ¿Qué es Axios?

> Axios es una biblioteca cliente HTTP basada en promesas para Node.js y navegadores. Nos facilita hacer peticiones HTTP/HTTPS (GET, POST, PUT, DELETE, etc.), manejar respuestas, configurar encabezados, timeouts y procesar errores de forma sencilla.

Nos interesa porque nos permite automatizar solicitudes web rápidamente desde Node.js —por ejemplo para fuzzing básico, comprobaciones de reflexión (reflected XSS), consultas a APIs, o como base para herramientas de escaneo.

---

## Instalación

Desde un proyecto Node.js:

```bash
npm init -y
npm install axios
```

O usando `yarn`:

```bash
yarn add axios
```

---

## Uso básico

### 1. Petición GET simple

```javascript
const axios = require('axios');

(async () => {
  try {
    const res = await axios.get('https://example.com');
    console.log(res.status);       // Código HTTP
    console.log(res.headers);      // Encabezados de respuesta
    console.log(res.data);         // Cuerpo (HTML, JSON, etc.)
  } catch (err) {
    console.error('Error:', err.message);
  }
})();
```

### 2. Petición con parámetros de consulta

```javascript
const res = await axios.get('https://example.com/search', {
  params: { q: 'injection test', page: 1 }
});
```

Axios se encarga de codificar `params` correctamente en la query string.

### 3. Petición POST con JSON

```javascript
const res = await axios.post('https://api.example.com/login', {
  username: 'user',
  password: 'pass'
});
```

### 4. Encabezados y timeouts

```javascript
const res = await axios.get(url, {
  headers: { 'User-Agent': 'Mozilla/5.0', 'X-My-Header': 'PoC' },
  timeout: 8000
});
```

---

## Manejo de errores

Axios lanza excepciones (rechaza la promesa) en varios casos: errores de conexión, timeouts, y códigos HTTP fuera del rango 2xx.

```javascript
try {
  const res = await axios.get(url);
} catch (err) {
  if (err.response) {
    // La petición se realizó y el servidor respondió con un código fuera de 2xx
    console.error('Status:', err.response.status);
    console.error('Body:', err.response.data);
  } else if (err.request) {
    // La petición fue enviada pero no hubo respuesta
    console.error('No response received');
  } else {
    // Error al construir la petición
    console.error('Request error:', err.message);
  }
}
```

Esto nos permite diferenciar entre fallos de la aplicación (500), bloqueos (403, 401), o problemas de red.

---

## Configuración avanzada

### Agentes HTTP/HTTPS y certificados

Para manejar certificados autofirmados o ajustar agentes:

```javascript
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });

const res = await axios.get(url, { httpsAgent: agent });
```

> Atención: deshabilitar la verificación de certificados puede ser útil en entornos de laboratorio, pero nunca en producción.

### Instancias y configuración por defecto

Podemos crear una instancia con valores por defecto (útil para reutilizar cabeceras, baseURL, timeouts):

```javascript
const client = axios.create({
  baseURL: 'https://example.com',
  timeout: 10000,
  headers: { 'User-Agent': 'MyPoC/1.0' }
});

const res = await client.get('/path');
```

### Interceptores

Los interceptores permiten procesar solicitudes o respuestas globalmente (logging, modificar headers, etc.).

```javascript
client.interceptors.request.use(config => {
  console.log('Sending:', config.method, config.url);
  return config;
});

client.interceptors.response.use(resp => {
  // Normalizar o registrar
  return resp;
}, err => {
  // Manejo global de errores
  return Promise.reject(err);
});
```

---

## Ejemplos prácticos para pentesting

- **Detección rápida de reflexiones**: inyectar payloads en parámetros y buscar su aparición en `res.data` (como en el PoC que trabajamos).
    
- **Fuzzing básico**: iterar una lista de parámetros y payloads, registrar respuestas (status, latencia, contenido) para priorizar pruebas manuales.
    
- **Consulta a APIs internas**: cuando el objetivo expone endpoints JSON, podemos automatizar llamadas autenticadas, probar inputs y analizar respuestas.
    
- **Soporte para proxies**: usar `axios` detrás de un proxy (configurar `proxy` o `httpAgent`) para dirigir tráfico a Burp/OWASP ZAP y combinar con análisis manual.
    

---

## Buenas prácticas y limitaciones

- Añadir `timeout` y retry/backoff si iteramos muchos endpoints.
    
- Respetar `robots.txt` y _scope_ del engagement. No escalar pruebas sin permiso.
    
- Ten cuidado con la codificación y normalización al buscar reflexiones: muchas aplicaciones devuelven entidades HTML (`&lt;`, `&gt;`) que requieren decodificación para evaluar falsos positivos/negativos.
    
- Para ejecución real de payloads conviene complementar con un navegador automatizado (Puppeteer / Playwright) porque una coincidencia textual no garantiza ejecución.
    

---

## Pequeña checklist de uso en un PoC

1. Crear instancia con `axios.create()` y headers realistas.
    
2. Iterar parámetros/payloads con `params` o cuerpo `data`.
    
3. Registrar `status`, `latency` (usar `Date.now()` o interceptores), y `res.data` en bruto.
    
4. Normalizar/decodificar `res.data` antes de buscar payloads.
    
5. Si hay indicio, pasar a la prueba de ejecución con Puppeteer.
    

---

## Recursos y referencias rápidas

- Axios GitHub: [https://github.com/axios/axios](https://github.com/axios/axios)
    
- Documentación oficial: [https://axios-http.com/](https://axios-http.com/)
    

---
