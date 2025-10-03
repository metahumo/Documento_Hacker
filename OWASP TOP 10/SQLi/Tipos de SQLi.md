
---
# Comparativa: tipos de SQL Injection

En este documento presentamos de forma concisa las diferencias entre las tres variantes habituales de inyección SQL que nos encontraremos en pruebas de seguridad web: **error-based**, **boolean-based (conditional responses)** y **time-based**. La tabla y las notas nos ayudarán a retener las diferencias y a elegir la técnica apropiada según el comportamiento de la aplicación.

## Tabla comparativa

| Característica | Error-based | Boolean-based (respuestas condicionales) | Time-based |
|---|---:|---:|---:|
| Señal observable | Mensajes de error de la BD o contenido visible cambiado por un error. | Cambios en el contenido de la respuesta (presencia/ausencia de texto, diferencias en longitud o en encabezados). | Diferencias en el tiempo de respuesta (latencia inducida). |
| Ejemplo de comportamiento | Al inyectar `'` aparece un error SQL en la página. | Al inyectar una condición verdadera aparece "Welcome" y si es falsa no aparece. | Al inyectar una condición verdadera la respuesta tarda 5s más (por `sleep`). |
| Nivel de ruido / fiabilidad | Alto (si la app muestra errores). | Moderado: sensible a cambios no relacionados (session, balanceo). | Moderado/alto: más fiable contra aplicaciones que no muestran contenido distinguible, pero lento. |
| Facilidad para extraer datos | Rápido cuando es posible (se exfiltra en la respuesta). | Lento (extracción carácter a carácter). | Muy lento (extracción carácter a carácter con delay). |
| Detección automática | Fácil con herramientas si la app muestra errores. | Requiere comparar respuestas; buena para automatizar con cuidado. | Detectable por tiempo; útil cuando no hay diferencias de contenido. |
| Uso típico | Entornos donde la DB devuelve errores o mensajes detallados. | Entornos donde la app devuelve distintas vistas según una condición booleana. | Entornos donde la app no cambia contenido pero permite comandos que retrasan la ejecución. |

## Notas prácticas

- Error-based es el método más directo pero depende de que la aplicación muestre o filtre la salida de errores de la base de datos. En producción esto suele estar deshabilitado.
- Boolean-based (respuestas condicionales) es la forma común de "Blind SQLi" con menor ruido: construimos consultas cuya verdad/falsedad se refleja en el HTML. Nos permite extraer datos comparando respuestas entre payloads "true" y "false".
- Time-based es útil cuando no podemos distinguir el contenido entre respuestas, pero sí podemos forzar una pausa en la ejecución del servidor (por ejemplo `SLEEP()` o `pg_sleep()`); es la opción cuando la aplicación está muy limitante en su salida.
- En todos los casos, hay que tener en cuenta factores que generan falsos positivos/negativos: caché, balanceadores, variaciones de sesión, contenido dinámico y medidas de WAF/ratelimits.
- Antes de comenzar a extraer datos, siempre validar la inyección con pruebas controladas (por ejemplo comparando una condición obvia `1=1` vs `1=0`) y trabajar muy despacio para no interrumpir servicios ni exceder el scope autorizado.


---
