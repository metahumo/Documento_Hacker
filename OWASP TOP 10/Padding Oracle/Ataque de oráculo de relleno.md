# Ataque de Oráculo de Relleno (Padding Oracle Attack)

## 1. Introducción

En este documento explicamos qué es un **ataque de oráculo de relleno**, cómo funciona técnicamente y por qué representa una amenaza real en sistemas que usan cifrado por bloques (como CBC). Además, abordamos un **ejemplo práctico** y uno **real** para comprender mejor su funcionamiento y alcance.

---

## 2. ¿Qué es un oráculo de relleno?

Cuando hablamos de “oráculo” en este contexto, nos referimos a una respuesta del sistema que nos indica, directa o indirectamente, si una acción que probamos es válida o no. En este caso, el sistema actúa como un oráculo al decirnos si el **relleno** de los datos cifrados es correcto tras el intento de descifrado.

Esto se convierte en un vector de ataque cuando se puede usar esta información para **descifrar los datos sin conocer la clave de cifrado**.

---

## 3. Fundamentos técnicos

### 3.1. Cifrado por bloques

Algunos algoritmos criptográficos como AES funcionan sobre bloques de tamaño fijo. Si el mensaje no alcanza el tamaño necesario, se le añade **relleno** (padding) hasta completarlo. Un estándar común es **PKCS#7**, que especifica cómo debe construirse y validarse ese relleno.

### 3.2. CBC (Cipher Block Chaining)

CBC es un modo de operación donde:

- El primer bloque cifrado depende del **vector de inicialización (IV)**.
- Cada bloque siguiente se cifra a partir del **resultado del anterior**.
- Esta estructura permite cifrar el mismo mensaje de forma diferente usando el mismo algoritmo y clave.

### 3.3. El problema

Si un sistema revela explícita o implícitamente si el **relleno es válido**, un atacante puede modificar el mensaje cifrado (en concreto, bloques anteriores al que desea descifrar), observar la respuesta del sistema y, con paciencia, **descifrar el contenido original, byte por byte**.

---

## 4. Ejemplo práctico (simulado)

Supongamos que interceptamos una cookie cifrada en CBC como la siguiente:

```

Cookie: session=3a1f4e... (cadena en base64)

```

Vamos a modificar el último byte del penúltimo bloque cifrado y enviar esa nueva cookie al servidor. Si el servidor responde con algo como:

```

Error: Invalid padding

````

Sabemos que el relleno es incorrecto. Modificamos el byte de nuevo y volvemos a enviar la petición. Cuando el error cambia (por ejemplo, recibimos un "200 OK" o un error diferente), deducimos que hemos logrado un **relleno válido**, lo que implica que ese byte del texto plano **tiene un valor conocido**. Repetimos el proceso para cada byte del bloque.

### Herramienta: [[Padbuster]]

[PadBuster](https://github.com/GDSSecurity/PadBuster) automatiza este proceso:

```bash
perl padBuster.pl http://example.com/page.php cookie=XYZ 16
````

Esto nos permitirá ir probando valores automáticamente, identificando si el relleno fue válido, y finalmente obtener el mensaje descifrado.

---

## 5. Ejemplo real: Oracle BEA WebLogic (CVE-2010-3849)

Un caso conocido fue la vulnerabilidad en Oracle BEA WebLogic Server. Este software devolvía errores diferentes cuando los datos cifrados presentaban un **relleno inválido**. Un atacante podía modificar la cookie cifrada de sesión y observar la respuesta HTTP para descubrir si el relleno era correcto.

Gracias a esta información, fue posible recuperar información sensible y, en algunos casos, incluso ejecutar código malicioso aprovechando el contenido de la cookie decodificada.

---

## 6. Mitigación

Para protegernos contra este tipo de ataques:

- **Nunca debemos confiar en la validez del relleno** como única forma de autenticidad.
    
- Es necesario **verificar la integridad de los datos cifrados** antes de intentar descifrarlos, usando un HMAC (Hash-based Message Authentication Code).
    
- La comparación de HMAC debe hacerse en **tiempo constante**, para evitar otros tipos de ataques por canal lateral (como los de temporización).
    

> En resumen: validar la integridad **antes** de descifrar.

---

## 7. Conclusión

El ataque de oráculo de relleno demuestra cómo pequeños errores de implementación en criptografía pueden derivar en fallos graves de seguridad. A pesar de la complejidad técnica, hoy en día existen herramientas que permiten explotar estas fallas de forma semiautomática. Es crucial que, como profesionales de la ciberseguridad, entendamos estos vectores de ataque para saber identificarlos y mitigarlos en sistemas reales.

---

## 8. Laboratorio

A continuación, se proporciona el enlace directo de descarga a la máquina ‘Padding Oracle’ de **Vulnhub**, la cual estaremos importando en VMWare para practicar esta vulnerabilidad:

- **Pentester Lab** **– Padding Oracle**: [https://www.vulnhub.com/?q=padding+oracle](https://www.vulnhub.com/?q=padding+oracle)

---


