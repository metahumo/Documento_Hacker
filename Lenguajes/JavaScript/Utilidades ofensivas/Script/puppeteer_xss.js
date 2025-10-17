
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
