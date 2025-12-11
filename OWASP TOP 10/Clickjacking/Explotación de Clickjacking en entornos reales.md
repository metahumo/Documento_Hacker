
---

# Campañas de Clickjacking en la práctica: ejemplos, vectores modernos y riesgos reales

## 1. Recordatorio conceptual

El **clickjacking** consiste en engañar al usuario para que haga clic en un elemento legítimo de una aplicación, pero presentado de forma invisible o disfrazada bajo un contenido señuelo. El navegador del usuario realiza la acción sin que este sea consciente de estar interactuando con la aplicación objetivo.

El ataque se basa en:

- Embebido de la aplicación víctima dentro de un `<iframe>`
    
- Control visual mediante opacidad, recortes o solapamientos
    
- Un engaño mínimo: “haz clic aquí”, “comprueba tu puntuación”, “ver vídeo”, etc.
    
- El usuario realiza realmente la interacción, por lo que **no se rompen tokens CSRF ni protecciones de autenticación**
    

En esencia:

> El atacante controla lo que el usuario ve y el usuario controla el clic → juntos producen la acción maliciosa.

---

## 2. Ejemplos reales y documentados de clickjacking

### 2.1. Activación de funciones sensibles en redes sociales

Casos reales históricamente documentados incluyen:

- “Auto-like” en Facebook
    
- “Auto-follow” en Twitter
    
- “Auto-subscribe” en YouTube
    

El mecanismo era simple:

1. Un iframe se situaba justo bajo un botón señuelo (Play, Claim offer…)
    
2. La víctima hacía clic
    
3. En realidad estaba pulsando un botón real dentro de su sesión
    

Resultado:  
Amplificación masiva aprovechando la confianza social de la víctima.

### 2.2. Cambio de email o ajustes de seguridad en servicios SaaS

En plataformas SaaS pequeñas o mal configuradas:

- Formulario de cambio de correo sin medidas anti-frame
    
- Botón de “Save changes” embebido en iframe transparente
    
- El usuario hace clic sobre un contenido señuelo
    
- El formulario se envía → email tomado por el atacante
    

Consecuencia:

- Hijacking de cuenta combinando con password reset
    
- Persistencia y acceso prolongado
    

### 2.3. Paneles administrativos internos

Casos reales en empresas:

- Interfaces legacy sin X-Frame-Options ni CSP
    
- Usuarios autenticados durante toda la jornada
    
- Clickjacking usado para:
    
    - Crear usuarios administradores
        
    - Modificar ACLs
        
    - Habilitar servicios
        
    - Desactivar alertas
        

Este vector es especialmente crítico porque:

- No requiere explotar vulnerabilidades internas
    
- Basta que el empleado abra un enlace externo en su navegador corporativo
    

---

## 3. Vectores modernos de distribución

### 3.1. SEO como mecanismo de entrada

Patrón equivalente al observado en campañas modernas de CSRF:

- El atacante publica contenido SEO real, indexado y bien posicionado
    
- La víctima entra buscando algo legítimo (“plantillas Excel”, “trucos productividad”)
    
- La página embebe un iframe invisible de un SaaS donde la víctima está autenticada
    
- Clickjacking automático o semiautomático
    

Ventaja clave:

> La víctima llega por confianza en Google, no por un enlace sospechoso.

### 3.2. Redes sociales como delivery

Dinámica común:

- Enlace atractivo (“test de personalidad”, “oferta limitada”, “juega ahora”)
    
- Carga de iframe invisible
    
- Usuario hace clic en un elemento que coincide con un botón oculto del SaaS objetivo
    

Resultado típico:

- Cambios de settings
    
- Autorizar accesos
    
- Dar permisos a apps
    
- Seguir páginas o usuarios
    

### 3.3. Ingeniería social mínima

A diferencia del phishing:

- No hace falta convencer al usuario de introducir credenciales
    
- Basta con que pulse un botón que en apariencia no es peligroso
    

Por eso este ataque sigue vigente:  
**es simple, visual y extremadamente eficaz.**

---

## 4. Escenarios en contextos corporativos

### 4.1. Aplicaciones internas sin cabeceras anti-frame

Muchos paneles internos presentan:

- ausencia de `X-Frame-Options`
    
- CSP sin directiva `frame-ancestors`
    
- autologin persistente (SSO corporativo)
    
- endpoints sensibles accesibles por UI
    

Un atacante puede:

1. Enviar un enlace a un empleado
    
2. Embutir el panel interno en un iframe
    
3. Alinear un botón señuelo con un botón de “approve”, “add user”, “save config”…
    
4. Capturar privilegios o modificar configuraciones críticas
    

Este vector es uno de los más infravalorados en seguridad interna.

### 4.2. SaaS corporativos modernos sin configuración anti-clickjacking

Aunque las plataformas grandes suelen estar bien protegidas, muchas:

- herramientas de admin SaaS
    
- suites de productividad emergentes
    
- CRMs nuevos
    
- apps de RRHH de bajo coste
    

siguen permitiendo ser frameadas accidentalmente.

El riesgo se eleva si el SaaS:

- expone paneles sensibles accesibles sin reautenticación
    
- permite cambios críticos vía botón
    
- utiliza parámetros GET para precargar valores
    

### 4.3. Dispositivos e IoT basados en web

Sectores donde el clickjacking sigue siendo muy real:

- routers
    
- cámaras IP
    
- paneles industriales
    
- appliances
    
- NAS domésticos
    

Muchos no implementan cabeceras anti-frame, por lo que:

- “Enable remote admin”
    
- “Open port”
    
- “Reset configuration”
    

pueden activarse mediante un simple clic de la víctima.

---

## 5. Factores que permiten el éxito

Los elementos clave que facilitan el clickjacking:

1. **Ausencia de cabeceras anti-frame**
    
2. **Botones sensibles accesibles sin confirmación extra**
    
3. **Sesiones persistentes del usuario**
    
4. **Interfaces monolíticas totalmente controladas por HTML**
    
5. **Falta de reautenticación o MFA en acciones críticas**
    
6. **Ceguera del usuario: cree estar interactuando con contenido inocuo**
    
7. **Posibilidad de precargar formularios mediante GET**
    

A diferencia de CSRF:

> No necesitamos que la petición sea automática. Solo que el usuario pulse un botón que ya quería pulsar.

---

## 6. Motivos actuales por los que el clickjacking sigue vigente

- Defensas mal entendidas (“mi aplicación usa SameSite”, pero no sirve aquí)
    
- Implementaciones débiles de frame busters basados en JS
    
- Aparición de nuevas plataformas SaaS sin cabeceras robustas
    
- Proliferación de paneles internos legacy
    
- Falta de cobertura en auditorías modernas (se testea menos que CSRF)
    
- UI modernas con botones críticos accesibles sin confirmación
    

Además:

> El atacante no necesita acceso al origen cruzado ni romper CORS.

---

## 7. Combinaciones modernas con otros vectores

### 7.1. Clickjacking + CSRF

Muy potente si:

- el botón oculta una acción POST vulnerable
    
- se ejecuta un envío de formulario manipulado
    
- se aprovecha un iframe semitransparente
    

### 7.2. Clickjacking + XSS

Si se consigue XSS en un sitio vulnerable:

- se puede generar contenido que fuerza interacciones invisibles
    
- o se usa XSS para modificar la UI y facilitar el clickjacking
    

### 7.3. Clickjacking + phishing tradicional

Escenario:

- víctima recibe un correo con un enlace legítimamente atractivo
    
- ese enlace carga un sitio del atacante
    
- el primer clic modifica algo en un SaaS donde la víctima ya está autenticada
    

En algunos casos incluso se combinan:

- loaders falsos
    
- pop-ups de “aceptar cookies”
    
- animaciones distractoras
    

---

## 8. Contramedidas server-side esenciales

La defensa real contra clickjacking **no se basa en JavaScript**, sino en cabeceras y políticas del navegador:

### 8.1. X-Frame-Options

```
X-Frame-Options: DENY
```

o

```
X-Frame-Options: SAMEORIGIN
```

Bloquea el framing desde dominios externos.

### 8.2. Content-Security-Policy (CSP)

Directiva esencial:

```
Content-Security-Policy: frame-ancestors 'none';
```

O en entornos complejos:

```
Content-Security-Policy: frame-ancestors https://intranet.corp https://partner.example;
```

### 8.3. Deshabilitar acciones sensibles en GET

- No usar parámetros GET para precargar valores críticos
    
- Requerir POST siempre que haya mutación
    
- Añadir confirmaciones visuales obligatorias
    

### 8.4. Reautenticación en operaciones críticas

- Cambio de email
    
- Cambio de MFA
    
- Cambio de contraseña
    
- Añadir usuarios admin
    

El clickjacking pierde potencia si tras un clic el servidor pide:

- contraseña
    
- TOTP
    
- token físico
    
- push MFA
    

### 8.5. Usar UI con confirmaciones adicionales

Diálogo modal:

> “¿Seguro que quieres cambiar tu email?”

No evita el ataque por sí sola, pero eleva el coste del atacante.

---

## 9. Checklist empresarial

- Aplicar `X-Frame-Options: DENY` o `SAMEORIGIN`
    
- Definir `frame-ancestors` en CSP
    
- Evitar precarga de datos sensibles por GET
    
- Reautenticación obligatoria
    
- MFA en acciones de impacto
    
- Auditoría periódica de UI
    
- Revisar SaaS usados por la empresa
    
- Asegurar que paneles internos **no pueden ser frameados**
    
- Testing sistemático en pentest y auditorías
    

---

## 10. Modelo de ataque en flujo (resumen)

```
[1] Reconocimiento
    |
    +--> Identificación de página con acción crítica (botón)
    |
[2] Construcción del exploit
    |
    +--> iframe + opacidad + alineación
    +--> parámetro GET opcional
    |
[3] Entrega
    |
    +--> SEO
    +--> Redes sociales
    +--> Correo corporativo / intranet
    |
[4] Interacción mínima
    |
    +--> El usuario hace clic en un señuelo
    +--> En realidad activa un botón crítico
    |
[5] Post-explotación
    |
    +--> Hijacking de cuenta
    +--> Cambios de seguridad
    +--> Persistencia
    +--> Acceso lateral
```

---

## 11. Conclusión

El clickjacking sigue siendo un ataque **simple, efectivo y muy infravalorado**, que afecta especialmente a:

- paneles internos corporativos
    
- aplicaciones SaaS jóvenes
    
- dispositivos IoT
    
- servicios que no implementan cabeceras anti-frame
    
- interfaces con botones críticos sin protección adicional
    

Su éxito depende de:

- Confianza del usuario
    
- Falta de defensas server-side
    
- Interacción mínima requerida
    

La mitigación real exige **varias capas**, no un único mecanismo:

- Cabeceras anti-frame
    
- CSP estricta
    
- Reautenticación
    
- Confirmaciones
    
- Auditorías regulares
    

---
