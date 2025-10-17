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
