# Documento Hacker — Índice maestro

En este repositorio recopilamos, organizamos y documentamos todo lo que estamos aprendiendo sobre hacking y seguridad ofensiva. Nuestro objetivo es crear una guía práctica, reproducible y pedagógica que nos permita estudiar de forma intensiva y aplicar técnicas en laboratorios (HTB, VulnHub, PentesterLab) manteniendo siempre un enfoque ético y legal.

## Cómo usar este README
- Usamos este índice para navegar por las seis carpetas principales del repositorio.
- Cada carpeta contiene guías, ejemplos y recursos (scripts, capturas, ejercicios).
- Antes de ejecutar cualquier exploit o script, revisamos la sección de **Advertencias y ética**.

---

## Estructura principal (carpetas)

1. **Buffer Overflow**  
   Contiene materiales sobre explotación de desbordamientos de pila/heap, ejemplos paso a paso, PoC en C/Python y técnicas de mitigación (ASLR, NX, PIE). Ideal para practicar con máquinas de laboratorio y ejercicios de reversing.

2. **Gestores de contenido (CMS)**  
   Guías y casos prácticos sobre explotación en CMS populares (WordPress, Joomla, Drupal...), incluyendo enumeración, plugins vulnerables, escalada y hardening. Recomendado para entender vectores web reales.

3. **Herramientas**  
   Documentación y tutoriales sobre las herramientas que utilizamos: Burp Suite, Nmap, Gobuster, ffuf, ffprobe, Hashcat, Metasploit, etc. Incluye configuraciones, ejemplos de uso y capturas de pantalla.

4. **Machines**  
   Resoluciones y guías paso a paso de máquinas que hemos resuelto en plataformas como Hack The Box, VulnHub y PentesterLab. Cada máquina suele incluir enumeración, explotación y post-explotación.

5. **OWASP TOP 10**  
   Explicaciones, payloads y ejercicios relacionados con las categorías del OWASP Top 10 y vulnerabilidades web frecuentes (SQLi, XSS, RCE, SSRF, etc.). Incluye ejemplos prácticos y scripts de prueba.

6. **Técnicas**  
   Cheatsheets y técnicas transversales: enumeración, escalada de privilegios, pivoting, persistence, forense básico, manipulación de archivos, fuzzing, etc. Es la sección más "operativa".

---

## Índice rápido (enlaces a las carpetas)
- [Buffer Overflow](./Buffer%20Overflow/)
- [Gestores de contenido (CMS)](./Gestores%20de%20contenido%20(CMS)/)
- [Herramientas](./Herramientas/)
- [Machines](./Machines/)
- [OWASP TOP 10](./OWASP%20TOP%2010/)
- [Técnicas](./Técnicas/)

---

## Recomendaciones para mejorar la navegación y mantenibilidad
- Añadimos un `README.md` dentro de cada carpeta con:
  - Objetivos de la carpeta.
  - Índice de los archivos más relevantes.
  - Etiquetas de dificultad (Principiante / Intermedio / Avanzado).
- Normalizamos nombres de archivos y caminos (usar `-` o `_`, evitar espacios si lo preferimos).
- Añadimos una tabla de contenidos automática en los `README.md` principales con anclas.
- Comprobamos enlaces relativos y corregimos los que fallen.
- Añadimos metadatos en la cabecera de los documentos (fecha, autor, estado: borrador/revisado).

---

## Buenas prácticas y seguridad
- Nunca ejecutar exploits contra sistemas reales sin permiso escrito. Practicamos en entornos controlados.
- Redactamos y borramos credenciales/IPS sensibles antes de publicar.
- Añadimos una licencia y una nota legal/ética en el root:
  - Licencia (por ejemplo MIT) si queremos compartir el contenido.
  - Disclaimer legal: uso educativo, no nos responsabilizamos por usos indebidos.

---

## Cómo contribuir
- Fork → branch con prefijo `feature/` o `fix/` → pull request con explicación y pruebas.
- Cada PR debe incluir:
  - Resumen de cambios.
  - Archivos modificados.
  - Pruebas o capturas si aplica.
- Revisiones: asignamos etiquetas `needs-review`, `approved`.

---

## Contacto y planificación de estudio
- Podemos añadir un `ROADMAP.md` con rutas de aprendizaje (p. ej. Reconocimiento → Explotación → Post-explotación → Forense).
- Sugerimos incluir ejercicios con tiempo estimado y material requerido para jornadas intensivas de estudio.

---

## Advertencias legales y éticas
Nos comprometemos a usar este repositorio con fines educativos. No usamos técnicas aquí descritas contra sistemas sin autorización expresa. Si dudas sobre si un ejercicio o script puede ser ilegal en tu jurisdicción, consultamos antes.

---

**Última nota**  
Este índice está pensado para orientarnos y facilitar la navegación. Si quieres, generamos ahora los `README.md` individuales para cada carpeta con un índice más detallado y sugerencias de ejercicios por nivel.
