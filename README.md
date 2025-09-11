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

2. **CVE**

   Contiene documentación de vulnerabilidades conocidas (Common Vulnerabilities and Exposures), con su identificación oficial, explicación pedagógica y exploits asociados. Cada CVE incluye descripción del fallo, impacto, PoC adaptada a Python 3 cuando sea necesario, y pasos de explotación. Es un apartado clave para practicar con exploits públicos y comprender cómo aprovechar vulnerabilidades reportadas en entornos reales.

3. **Gestores de contenido (CMS)**  
   Guías y casos prácticos sobre explotación en CMS populares (WordPress, Joomla, Drupal...), incluyendo enumeración, plugins vulnerables, escalada y hardening. Recomendado para entender vectores web reales.

4. **Herramientas**  
   Documentación y tutoriales sobre las herramientas que utilizamos: Burp Suite, Nmap, Gobuster, ffuf, ffprobe, Hashcat, Metasploit, etc. Incluye configuraciones, ejemplos de uso y capturas de pantalla.

5. **Machines**  
   Resoluciones y guías paso a paso de máquinas que hemos resuelto en plataformas como Hack The Box, VulnHub y PentesterLab. Cada máquina suele incluir enumeración, explotación y post-explotación.

6. **Lenguajes**  
   Recopilación de vulnerabilidades, funciones peligrosas y malas prácticas específicas de distintos lenguajes de programación. Cada subapartado se centra en un lenguaje (PHP, Python, C, etc.) y documenta ejemplos de explotación reales, fragmentos de código vulnerable y su análisis. También incluye PoCs, payloads y notas sobre mitigación. El objetivo es entender cómo ciertas construcciones de código pueden derivar en fallos de seguridad y cómo se pueden aprovechar en un contexto ofensivo.

7. **OWASP TOP 10**  
   Explicaciones, payloads y ejercicios relacionados con las categorías del OWASP Top 10 y vulnerabilidades web frecuentes (SQLi, XSS, RCE, SSRF, etc.). Incluye ejemplos prácticos y scripts de prueba.

8. **Técnicas**  
   Cheatsheets y técnicas transversales: enumeración, escalada de privilegios, pivoting, persistence, forense básico, manipulación de archivos, fuzzing, etc. Es la sección más "operativa".

---

## Índice rápido (enlaces a las carpetas)
- [Buffer Overflow](./Buffer%20Overflow/)
- [CVE](./CVE/)
- [Gestores de contenido (CMS)](./Gestores%20de%20contenido%20(CMS)/)
- [Herramientas](./Herramientas/)
- [Lenguajes](./Lenguajes/)
- [Machines](./Machines/)
- [OWASP TOP 10](./OWASP%20TOP%2010/)
- [Técnicas](./Técnicas/)

---

## Créditos

El contenido y los scripts de este repositorio están inspirados y extraídos de materiales creados por la comunidad de ciberseguridad.  

**Todo el mérito corresponde a sus autores originales.**

- [s4vitar](https://github.com/s4vitar)  
- [Hack The Box](https://www.hackthebox.com)  
- [PentesterLab](https://pentesterlab.com)  
- [PayloadsAllTheThings (by swisskyrepo)](https://github.com/swisskyrepo/PayloadsAllTheThings)  
- [HackTricks Wiki](https://github.com/HackTricks-wiki/hacktricks)  
- [PayloadBox XSS Payload List](https://github.com/payloadbox/xss-payload-list)  

Este repositorio no pretende apropiarse del trabajo de terceros, sino centralizar y reutilizar material educativo con fines de aprendizaje.

---

## Buenas prácticas y seguridad
- Nunca ejecutar exploits contra sistemas reales sin permiso escrito. Practicamos en entornos controlados.
  
---

## Cómo contribuir
- Fork → branch con prefijo `feature/` o `fix/` → pull request con explicación y pruebas.
- Cada PR debe incluir:
  - Resumen de cambios.
  - Archivos modificados.
  - Pruebas o capturas si aplica.
- Revisiones: asignamos etiquetas `needs-review`, `approved`.


---

## Advertencias legales y éticas
Nos comprometemos a usar este repositorio con fines educativos. No usamos técnicas aquí descritas contra sistemas sin autorización expresa. Si dudas sobre si un ejercicio o script puede ser ilegal en tu jurisdicción, consultamos antes.

---

