
---
# Asignación de espacio para el Shellcode

## Introducción

Una vez que hemos identificado el **offset exacto** en un desbordamiento de búfer y hemos sobrescrito con éxito el registro **EIP**, el siguiente paso lógico es determinar **dónde se encuentran los caracteres adicionales que inyectamos** en la memoria del proceso. Esta información es esencial porque **ahí es donde ubicaremos nuestro shellcode**.

## ¿Qué ocurre tras sobrescribir EIP?

Cuando continuamos escribiendo datos tras haber alcanzado y sobrescrito el EIP, esos datos suelen almacenarse justo después en la **pila (stack)**. En muchos escenarios, estos datos estarán apuntados por el registro **ESP** (Extended Stack Pointer).  
Esto tiene sentido porque:

- ESP señala la parte superior de la pila.
- En un buffer overflow típico, los datos adicionales se “desbordan” hacia la pila.

En Immunity Debugger o cualquier otro depurador, podemos ver exactamente dónde se colocan estos bytes y confirmar que caen en la dirección que apunta ESP.

## ¿Qué es el Shellcode?

El **shellcode** es una secuencia de instrucciones en lenguaje máquina diseñada para ejecutar una acción concreta, como abrir una shell inversa o ejecutar comandos arbitrarios. Nuestro objetivo es **colocar este shellcode en la pila**, justo en la región de memoria que controlamos, para que pueda ejecutarse.

## ¿Cómo lo ejecutamos?

Una vez que el shellcode está en la pila, debemos asegurarnos de que **el flujo de ejecución del programa salte hacia esa dirección de memoria**, es decir, que EIP apunte a ESP (o cerca de ESP).

Una técnica común es usar una instrucción de tipo `JMP ESP` o `CALL ESP`, que nos redirige directamente a nuestro shellcode.

---

## Ejemplo práctico

Supongamos el siguiente escenario:

- Hemos identificado que el **offset** del EIP se encuentra en el byte 200.
- Sabemos que después del byte 200, el registro **ESP** apunta justo a nuestros datos adicionales.

Entonces diseñamos nuestro exploit así:

```python
padding = b"A" * 200              # Llenamos hasta llegar a EIP
eip = b"\xB4\x10\x50\x62"         # Dirección de JMP ESP (por ejemplo en alguna DLL sin protección)
nop_sled = b"\x90" * 16           # Espacio de NOPs para asegurar el aterrizaje
shellcode = b"\xcc" * 100         # Shellcode de prueba: 100 INT3 (breakpoints) como ejemplo

payload = padding + eip + nop_sled + shellcode
````

- `b"A" * 200`: Alcanza el EIP.
    
- `eip`: Dirección que contiene una instrucción `JMP ESP` dentro del programa o alguna DLL cargada.
    
- `NOP sled`: Zona de relleno que permite que el salto caiga con mayor margen de error.
    
- `shellcode`: Aquí iría el payload real (una reverse shell, por ejemplo).
    

Una vez ejecutamos este exploit, si todo está correctamente alineado, el flujo del programa saltará al ESP, y el shellcode se ejecutará desde la pila.

---

## Consideraciones importantes

- **Compatibilidad:** El shellcode debe estar diseñado para la arquitectura de destino (x86, x64, etc.) y sistema operativo (Windows, Linux…).
    
- **Badchars:** Algunos caracteres (como `\x00`, `\x0A`, `\x0D`) pueden romper el shellcode. Debemos identificarlos antes de generar el shellcode.
    
- **Protecciones:** DEP, ASLR y otras mitigaciones modernas pueden impedir este tipo de ataques si no se evitan adecuadamente.
    

---

## Conclusión

La asignación de espacio para el shellcode es una parte fundamental del proceso de explotación. Una vez controlamos el EIP, debemos asegurarnos de que nuestro shellcode se encuentre en una región de memoria accesible (como la pila) y luego redirigir la ejecución hacia esa región. Comprender esta etapa nos permite **convertir un simple crash en una ejecución arbitraria de código**.

---

## Cheatsheet

```txt
- ESP = Extended Stack Pointer, apunta al inicio de la pila
- JMP ESP = instrucción común para redirigir ejecución hacia el shellcode
- NOP sled = zona de aterrizaje segura para el shellcode
- Offset = número exacto de bytes hasta llegar al EIP
- Shellcode = código malicioso o útil que deseamos ejecutar
```

---
