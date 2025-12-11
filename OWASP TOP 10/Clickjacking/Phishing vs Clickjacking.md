
---

# Phishing vs Clickjacking en la práctica: diferencias reales y cómo llega un iframe a una víctima

## 1. Escenario inicial: la búsqueda de “zapatillas Nike”

Cuando una persona busca “zapatillas Nike”, llega a una página que **parece la oficial**, pero el dominio no pertenece a la marca. Ese caso no implica clickjacking. Forma parte de otra familia de ataques:

- **Phishing**
    
- **Suplantación visual del sitio original**
    
- **SEO poisoning** (el atacante manipula resultados de búsqueda)
    
- **Typosquatting** (dominios similares: `n1ke.com`, `nike-shop.net`)
    
- **Fake e-commerce** para robar datos o dinero
    

En este tipo de fraude:

- El atacante crea una **web falsa desde cero**
    
- La víctima interactúa con una página clonada pero **ajena a la marca**
    
- No se cargan iframes invisibles
    
- No se superponen elementos
    
- No hay clics “engañados”
    

La técnica se basa únicamente en:

> **Engaño visual + captura de credenciales o información financiera**

---

## 2. Qué es realmente el clickjacking

El clickjacking es algo completamente distinto.

Aquí el atacante **no copia la web**.  
En su lugar:

1. **Carga la web legítima dentro de un iframe**
    
2. Hace ese iframe **invisible** (opacidad, z-index)
    
3. Coloca un botón falso encima
    
4. La víctima cree que hace clic en el señuelo
    
5. El clic real impacta en el botón auténtico del sitio objetivo
    

Ejemplo clásico:

- Ves un botón: “Haz clic para ganar un premio”
    
- Pero debajo está `twitter.com/settings/deactivate` dentro de un iframe transparente
    
- Pulsas → estás desactivando tu cuenta real
    

La idea clave:

> **Clickjacking = usar la web real en un iframe invisible para inducir acciones sin que la víctima lo sepa.**

---

## 3. Diferencia esencial (resumen rápido)

|Caso|Qué ve el usuario|Qué usa el atacante|Qué ocurre|
|---|---|---|---|
|**Phishing**|Una web falsa que parece real|Copia visual del sitio|Robo de datos, contraseñas o pagos|
|**Clickjacking**|Una web “inocente” con capa falsa|Iframe invisible con la web real|Clic involuntario en acciones auténticas|

---

## 4. ¿Cómo llega un iframe a una víctima en la vida real?

Un iframe no “viaja” en un mensaje.  
En la práctica, lo que ocurre es:

> La víctima visita una web que contiene un iframe malicioso.

Para que la víctima cargue ese iframe, el atacante necesita **solo una cosa: tráfico** hacia una página que él controla. Y esto se consigue mediante varios vectores.

### 4.1. Hosting propio del atacante

El método más básico:

- El atacante crea un HTML malicioso
    
- Lo sube a su hosting
    
- Inserta el iframe apuntando al sitio vulnerable
    

Ejemplo:

```
https://malicious-attacker-domain.com/click.html
```

Si la víctima está autenticada en la web objetivo, el iframe se carga y el ataque se dispara.

Este escenario es el equivalente real al **“Exploit server”** de PortSwigger.

---

### 4.2. Phishing o ingeniería social

El atacante distribuye la URL maliciosa mediante:

- Correo
    
- SMS
    
- WhatsApp
    
- Redes sociales
    
- Un QR en una pegatina o cartel
    

Ejemplos típicos:

- “Tu factura está lista. Pulsa aquí.”
    
- “Mira estas fotos tuyas.”
    
- “Tienes una notificación pendiente.”
    

La víctima entra en la página → el iframe se carga → el señuelo manipula el clic.

---

### 4.3. Publicidad maliciosa (Malvertising)

Otra vía real:

- El atacante compra anuncios en redes publicitarias baratas
    
- El anuncio redirige a una página controlada por él
    
- Esa página incluye el iframe malicioso
    

Ventaja:

> El atacante no necesita contactar directamente con la víctima.

---

### 4.4. Blogs, foros o artículos comprometidos

Si un atacante compromete un sitio legítimo, puede insertar:

```html
<iframe src="https://sitio-vulnerable.com/accion"></iframe>
```

Esto es muy eficaz porque:

- La víctima confía en la web original
    
- No existe sospecha
    
- El payload se ejecuta automáticamente al cargar la página
    

Incluso sin hackear nada, algunos CMS permiten subir contenido con HTML sin filtrar.

---

### 4.5. Plataformas que permiten HTML embebido

En entornos corporativos o educativos:

- Blogs con HTML habilitado
    
- Wikis internas
    
- Herramientas low-code/no-code que permiten bloques HTML
    
- Portales corporativos sin política de filtrado estricta
    

El atacante inserta el iframe, y el navegador hace el resto.

---

### 4.6. XSS (Cross-Site Scripting)

El vector óptimo para clickjacking avanzado.

Si el atacante encuentra un XSS en una web legítima:

```html
<iframe src="https://victim.com/accion-sensible"></iframe>
```

Esto es crítico porque:

> La víctima ni siquiera tiene que abandonar el sitio real.  
> El iframe se inyecta dentro de la propia aplicación que confía.

---

## 5. ¿Qué hace el navegador cuando carga ese iframe?

La secuencia real es simple:

1. La víctima abre la web controlada por el atacante
    
2. El navegador procesa su HTML
    
3. Encuentra un `<iframe>` apuntando al sitio objetivo
    
4. Carga **la web real** dentro de ese iframe
    
5. Si la web no tiene defensas (`X-Frame-Options`, `frame-ancestors`) se renderiza
    
6. El atacante coloca un señuelo encima
    
7. La víctima hace clic
    
8. El clic se transmite al iframe
    
9. La acción real se ejecuta con la sesión de la víctima
    

---

## 6. Entonces… ¿qué representa “Deliver exploit to victim”?

En laboratorios PortSwigger:

- Es un simple **botón** que simula el paso de distribuir el exploit.
    

En la vida real, equivale a:

- Enviar un enlace malicioso
    
- Alojarlos en sitios populares
    
- Insertarlo en un blog comprometido
    
- Usar un anuncio
    
- Insertar el payload mediante XSS
    
- Usar ingeniería social para que la víctima visite la página
    

En todos los casos:

> El atacante solo necesita que la víctima cargue una página que él controla. Nada más.


---

## 7. La regla de oro es:

**Clonación: cuando el atacante necesita recibir información.**

→ phishing, robo de credenciales, datos bancarios, etc.

**Iframe (clickjacking): cuando el atacante necesita que la víctima ejecute acciones en un sitio real.**

→ likejacking, followjacking, transferencias, cambios de estado…

---
