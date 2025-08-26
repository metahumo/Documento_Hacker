
---
# Introducción al Buffer Overflow

En este apartado vamos a estudiar una de las vulnerabilidades más clásicas y peligrosas en el ámbito del hacking ético: el **buffer overflow** o desbordamiento de búfer.

El buffer overflow se produce cuando un programa intenta escribir más datos de los que puede almacenar un búfer, sobrescribiendo zonas de memoria adyacentes. Esta sobreescritura puede afectar al funcionamiento normal del programa y, en casos más avanzados, permitir a un atacante alterar el flujo de ejecución del código.

## ¿Qué es un búfer?

Un búfer es simplemente una zona de memoria reservada para almacenar datos temporales. En muchos lenguajes de bajo nivel, como C, la gestión de memoria es manual y no existe una verificación automática del tamaño de los datos que se copian en el búfer. Esto abre la puerta a errores de programación que pueden derivar en vulnerabilidades.

## ¿Por qué es peligroso?

Si un atacante logra sobrescribir partes sensibles de la memoria, como la dirección de retorno de una función, podría redirigir el flujo del programa a código malicioso que él mismo haya inyectado. Esto puede llevar a:

- Ejecución arbitraria de código
- Escalada de privilegios
- Robo de información sensible
- Toma de control total del sistema

## Ejemplo básico en C

Veamos un ejemplo muy simple de código vulnerable a buffer overflow:

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char buffer[16];
    printf("Introduce una cadena: ");
    gets(buffer);  // ¡Función peligrosa! No comprueba límites
    printf("Has introducido: %s\n", buffer);
}

int main() {
    vulnerable_function();
    return 0;
}
````

Este programa declara un búfer de 16 bytes y utiliza `gets()` para almacenar en él la cadena introducida por el usuario. El problema es que `gets()` no comprueba la longitud de entrada: si introducimos más de 16 caracteres, estaremos sobrescribiendo memoria fuera del búfer.

Esto por sí solo puede provocar un **fallo de segmentación** (segfault), pero también puede explotarse para ejecutar código arbitrario si el entorno lo permite (por ejemplo, en sistemas sin protecciones modernas como ASLR, DEP, etc.).

## Objetivo de esta sección

Nuestro objetivo en esta sección será entender:

- Cómo se produce un buffer overflow a nivel de memoria
    
- Cómo identificar funciones vulnerables en código fuente
    
- Cómo explotar esta vulnerabilidad en entornos controlados
    
- Qué técnicas de mitigación existen y cómo funcionan
    

Vamos a practicar sobre binarios vulnerables que compilaremos nosotros mismos, y en algunos casos, desarrollaremos nuestros propios exploits paso a paso.

---
