# CONTRIBUTING.md

Nosotros agradecemos cualquier contribución que mejore este repositorio. El objetivo de este documento es facilitar que colaboremos de forma ordenada, segura y pedagógica.

## Antes de contribuir
- Este repositorio es para **fines educativos**. Antes de enviar contenidos, revisamos que no incluyan credenciales, claves, direcciones IP públicas no autorizadas ni información sensible.
- Si la contribución introduce exploits o técnicas que pueden ser peligrosas, añadimos una nota clara de uso responsable y limitamos ejemplos a entornos de laboratorio.

## Flujo de trabajo (workflow)
1. **Fork** del repositorio.
2. Creamos una rama desde `main` con el prefijo apropiado:
   - `feature/` para nuevas guías o materiales.
   - `fix/` para correcciones.
   - `doc/` para cambios en documentación.
   - `chore/` para tareas de mantenimiento.
   Ejemplo: `feature/ffuf-cheatsheet`.

3. Hacemos commits pequeños y atómicos con mensajes en **imperativo** y en español:
   - Formato: `tipo: descripción breve`
   - Ejemplos: `doc: añadir índice a OWASP TOP 10`, `fix: corregir comando nmap en Reconocimiento`.

4. Abrimos un **Pull Request** contra `main` indicando:
   - Resumen de cambios.
   - Archivos modificados.
   - Pasos para probar (si aplica).
   - Nivel de dificultad y categoría (ej. `Intermedio - Enumeración`).

## Estilo y formato
- Usamos Markdown simple y claro.
- Encabezados: `#`, `##`, `###` según jerarquía.
- Bloques de código con el lenguaje: <code>```bash</code>, <code>```python</code>, etc.
- Evitamos iconos y emojis en los archivos principales.
- Normalizamos nombres de archivo usando `kebab-case` (sin espacios): `reconocimiento-web.md`.
- Si añadimos imágenes, las guardamos en carpetas `Imágenes/` dentro de la carpeta correspondiente y usamos rutas relativas.

## Plantilla para Issues
Al abrir un issue, rellenamos:
- **Título**: claro y conciso.
- **Descripción**: qué problema o propuesta.
- **Pasos para reproducir** (si corresponde).
- **Resultado esperado / resultado actual**.
- **Entorno**: SO, versión de la herramienta, enlaces relevantes.
- **Capturas** (si aplica).

## Pull Request (PR) checklist
- [ ] El PR tiene un título descriptivo.
- [ ] El PR incluye una descripción con propósito y cambios principales.
- [ ] No se han subido credenciales ni datos sensibles.
- [ ] Los archivos siguen la convención de nombres.
- [ ] Si se ha añadido código ejecutable, se incluyen instrucciones para probarlo.
- [ ] Se ha referenciado el issue relacionado (si aplica).

## Revisión y aceptación
- Las revisiones son realizadas por al menos una persona del equipo.
- Comentarios en cambios deben ser respondidos antes de la fusión.
- Podemos exigir cambios si la calidad o la seguridad lo requieren.

## Seguridad y divulgación responsable
- Si descubrimos una vulnerabilidad real (en software de terceros o en ejemplos), seguimos un **proceso de divulgación responsable**: no publicamos explotables en repositorios públicos sin coordinación.
- Para notificar fallos de seguridad, contactamos a: `metahumo@outlook.com`.
- Si alguien envía un exploit o técnica sensible, lo tratamos como `private` hasta evaluar el riesgo.

## Licencia y atribución
- Las contribuciones se publican bajo la licencia del repositorio (ver `LICENSE`).  
- Si usamos material ajeno (tutoriales, snippets), citamos la fuente y respetamos la licencia original.

## Herramientas de calidad (recomendadas)
- Usar linters Markdown (markdownlint).
- Revisar enlaces rotos.
- Comprobar ortografía.

## Agradecimientos
Gracias por colaborar. Si quieres ayuda para preparar tu PR, te orientamos sobre cómo estructurarlo y las pruebas necesarias.
