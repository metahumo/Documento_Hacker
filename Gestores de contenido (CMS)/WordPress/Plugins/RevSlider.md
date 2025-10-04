
---
# Qué falló en RevSlider

En este documento vamos a explicar de forma pedagógica por qué el plugin **RevSlider** (Revolution Slider) fue culpable de un porcentaje tan alto de intrusiones en sitios WordPress en 2016, qué técnicas usaban los atacantes y cómo podemos proteger nuestras instalaciones. Vamos a estructurarlo en fases (reconocimiento, explotación, impacto y mitigación) y terminar con una lista de pasos prácticos que podemos ejecutar ya.

---

## Resumen ejecutivo

En 2016 la firma Sucuri identificó que cerca del 10% de los compromisos exitosos contra sitios WordPress se debían a vulnerabilidades en RevSlider. Aunque las vulnerabilidades fueron reportadas y parcheadas desde 2014, la presencia del plugin dentro de temas, instalaciones desactualizadas y la falta de mantenimiento en muchos sitios permitieron que la explotación continuara y derivara en campañas masivas (más de 100.000 sitios comprometidos en la campaña reportada).

---

## 1. ¿Por qué un solo plugin puede causar tantos compromisos?

Nosotros debemos entender varios factores que multiplican el riesgo:

- **Popularidad y distribución:** RevSlider era (y en muchos casos sigue siendo) distribuido tanto como plugin independiente como integrado dentro de temas comerciales. Eso aumenta su huella en millones de sitios.
    
- **Vulnerabilidades críticas y explotables remotamente:** las fallas permitían operaciones peligrosas como lectura arbitraria de archivos y carga/ejecución de código vía peticiones HTTP sencillas.
    
- **Actualizaciones no aplicadas:** muchos administradores no aplican parches o no actualizan temas que incluyen versiones antiguas del plugin.
    
- **Automatización por parte de atacantes:** los atacantes realizaron barridos automáticos y explotación masiva; cuando un vector es fácil de explotar a escala, el número de compromisos crece muy rápido.
    

---

## 2. Fase de reconocimiento (cómo buscaban el plugin)

En la fase de reconocimiento los atacantes escanean rutas típicas en busca de RevSlider. Nosotros, como defensores, debemos saber que existen múltiples rutas posibles porque el plugin puede estar en distintos lugares según cómo se haya instalado o empaquetado por un tema.

Ejemplos de rutas que los atacantes exploraban:

```
/wp-content/themes/.../revslider/temp/update_extract/revslider/
/wp-content/plugins/.../revslider/temp/update_extract/
/wp-content/plugins/.../revslider/temp/update_extract/revslider/
//wp-content/plugins/revslider/
/wp-content/plugins/meteor-extras/includes/bundles/revslider/temp/update_extract/
/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php
/revslider.php
```

Los atacantes también probaban cientos de nombres de recursos y variaciones en los nombres de los temas. Por eso la búsqueda no se limitaba a una sola URL: era amplia y automatizada.

**Herramienta útil para detectar plugins y realizar enumeración:**

```bash
wpscan --enumerate ap
```

> Nota: este escaneo puede generar carga en el servidor; debemos usarlo con responsabilidad y, preferiblemente, en entornos de prueba o con permiso del propietario.

---

## 3. Fase de explotación (vectores usados)

Las vulnerabilidades explotadas permitían, entre otras cosas:

1. **Descarga arbitraria de archivos** desde el servidor web. Por ejemplo, una petición como:
    

```
http://victima.com/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php
```

permitía acceder a `wp-config.php`, con datos sensibles (credenciales de BD, sal de autenticación, etc.). Con esa información un atacante puede comprometer la base de datos o escalar el acceso.

2. **Inclusión y modificación de archivos / ejecución remota** mediante funciones del plugin que procesaban datos enviados por POST. Por ejemplo, llamadas a `revslider_ajax_action` con parámetros manipulados permitían escribir o modificar ficheros en el servidor.
    

Ambos vectores son especialmente peligrosos porque pueden automatizarse: leer `wp-config.php` y luego usar las credenciales para acciones adicionales o subir webshells.

---

## 4. Impacto real

Los compromisos derivados de estas explotaciones incluyen:

- Acceso a bases de datos y exfiltración de credenciales.
    
- Inserción de código malicioso (webshells, backdoors) y pivoteo dentro del servidor.
    
- Uso del sitio comprometido para distribuir malware, lanzar campañas SEO maliciosas o participar en redes de propagación.
    

Dado que muchas instalaciones no se parcheaban, los atacantes podían reutilizar las mismas técnicas meses o años después.

---

## 5. Soluciones y medidas defensivas (pasos prácticos)

Nosotros proponemos el siguiente plan de acción, ordenado y sencillo de ejecutar:

### 5.1 Verificar presencia de RevSlider

Usamos WPScan u otras herramientas de enumeración:

```bash
wpscan --enumerate ap
```

También podemos buscar manualmente rutas comunes (ejemplo con curl):

```bash
curl -I https://victima.com/wp-admin/admin-ajax.php?action=revslider_show_image
curl -I https://victima.com/wp-content/plugins/revslider/
```

### 5.2 Actualizar plugin y temas

- Si RevSlider está instalado como plugin independiente, actualizarlo desde el repositorio o desde el proveedor del plugin.
    
- Si RevSlider viene incluido en un tema, debemos actualizar el tema a su versión más reciente o contactar con el autor del tema para que lo actualice. Actualizar _el tema_ es tan importante como actualizar el plugin.
    

### 5.3 Revisar y eliminar archivos comprometidos

- Buscar y eliminar webshells y archivos no reconocidos.
    
- Revisar `wp-config.php` y credenciales; en caso de sospecha, cambiar contraseñas y rotar claves.
    

### 5.4 Escanear la instalación completa

Volver a ejecutar WPScan o herramientas de análisis (Sucuri, plugins de seguridad) para verificar que no queden vulnerabilidades abiertas.

### 5.5 Buenas prácticas adicionales

- Mantener WordPress, plugins y temas actualizados regularmente.
    
- No usar temas o plugins abandonados o de fuentes no confiables.
    
- Restringir accesos a `wp-admin` y `wp-includes` cuando sea posible (firewall de aplicaciones web, controles de acceso por IP).
    
- Habilitar copias de seguridad periódicas y almacenar backups fuera del servidor principal.
    

---

## 6. Recomendaciones para la respuesta ante incidentes

Si detectamos actividad sospechosa o confirmamos una intrusión, seguimos este orden:

1. Poner en cuarentena (si procede) la instancia comprometida.
    
2. Hacer un backup forense (copiar archivos y base de datos para análisis).
    
3. Cambiar todas las credenciales sensibles (usuarios admin, bases de datos).
    
4. Eliminar puertas traseras y parches temporales; actualizar plugin/tema.
    
5. Reinstalar desde fuentes limpias si la integridad está comprometida.
    

---

## 7. Conclusión

RevSlider ilustró cómo la combinación de popularidad, vulnerabilidades críticas, integración en temas y falta de mantenimiento provoca un riesgo sistémico. Nosotros debemos adoptar medidas preventivas continuas: vigilancia, actualización y procedimientos de respuesta ante incidentes para minimizar la probabilidad y el impacto de este tipo de ataques.

---

## Referencia

Artículo usado como referencia:

[https://henryraul.wordpress.com/2017/01/11/revslider/](https://henryraul.wordpress.com/2017/01/11/revslider/)

---

## Anexo: ejemplo de rutas y recursos escaneados (muestra)

Las rutas y recursos probados por atacantes son numerosas; a modo de muestra, incluimos algunas rutas y peticiones típicas (no exhaustivo):

```
/wp-content/themes/.../revslider/temp/update_extract/revslider/
/wp-content/plugins/.../revslider/temp/update_extract/
/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php
/wp-admin/admin-ajax.php?action=revslider_ajax_action&client_action=get_captions_css
/revslider.php
```

Ver algunos endpoints y temas probados por los atacantes [SecLists](./SecLists)

---
