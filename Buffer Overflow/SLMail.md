
---
# Práctica con SLMail: entorno y objetivo

Antes de comenzar a explotar vulnerabilidades reales, necesitamos configurar un entorno controlado en el que podamos practicar de forma segura y didáctica. En esta sección vamos a preparar todo lo necesario para realizar un buffer overflow contra la aplicación **SLMail**.

## Entorno necesario

Para poder llevar a cabo esta práctica, es imprescindible montar un entorno Windows vulnerable que nos permita:

- Ejecutar binarios sin protecciones modernas
- Analizar procesos con un depurador
- Ver en tiempo real cómo impacta un desbordamiento de búfer en la memoria

### Herramientas necesarias

Necesitaremos instalar lo siguiente:

- **Windows 7 Home Premium**  --> Se proporciona un `.ova` preconfigurado con Immunity Debugger y Mona.py ya configurados, así como el firewall desactivado.
  Descarga: [Uptodown](https://mega.nz/file/vixi2QKA#Bn1OfhLVWKXizJCis1ju4rleao7FpFHGHGukwnet1_M)  
  Es una versión ideal para pruebas de explotación por carecer de protecciones como ASLR o DEP en muchos casos.

- **Immunity Debugger**  
  Descarga: Immunity Debugger
  Lo usaremos para analizar la memoria en tiempo real, poner breakpoints y seguir la ejecución del programa vulnerable.

- **Mona.py**  
  Descarga: [mona.py (GitHub)](https://raw.githubusercontent.com/corelan/mona/master/mona.py)  
  Un plugin para Immunity Debugger que facilita la búsqueda de instrucciones útiles, offsets, y otras tareas durante el desarrollo de exploits.

- **SLMail 5.5.0.4433**  
  Descarga: [SLMail en Software Informer](https://slmail.software.informer.com/download/)  
  Esta es la aplicación vulnerable que usaremos como objetivo. Incluye un servicio POP3 que presenta un buffer overflow clásico.

### Configuración adicional: desactivar DEP

Es importante que **desactivemos el DEP (Data Execution Prevention)** dentro del sistema Windows. 

> Si no lo hacemos, los exploits que intentemos desarrollar probablemente no funcionarán, ya que DEP impide que se ejecute código en zonas de memoria marcadas como no ejecutables.

#### ¿Qué es DEP?

> DEP es una medida de seguridad moderna que protege la memoria frente a la ejecución de código malicioso. Funciona marcando ciertas zonas de memoria (como la pila o el heap) como no ejecutables. Si un programa intenta ejecutar instrucciones desde esas zonas, se lanza una excepción y el proceso se detiene.

Esta protección es eficaz contra muchos exploits basados en buffer overflow, que suelen intentar inyectar *shellcode* en esas regiones de memoria. Por eso, para fines educativos y de análisis, vamos a desactivarlo en nuestro entorno de laboratorio.

---

## ¿Qué es SLMail y por qué lo usamos?

> **SLMail** es un servidor de correo electrónico para Windows que contiene una vulnerabilidad conocida en su implementación del protocolo POP3. Es una aplicación ideal para aprendizaje porque:

- El desbordamiento de búfer es reproducible y estable
- El binario es fácil de analizar con Immunity Debugger
- Existen múltiples puntos de entrada para pruebas
- Es un ejemplo clásico usado en formación de exploits desde hace años

Lo que haremos será atacar su servicio POP3, enviando una cadena cuidadosamente diseñada que sobrescriba partes críticas de la memoria, como el puntero de instrucción (EIP), para redirigir la ejecución a nuestro propio código malicioso.

---

En el siguiente repositorio veremos paso a paso cómo identificar el punto vulnerable, calcular el offset exacto, y controlar el flujo de ejecución dentro de SLMail.


---

Acción:

```bash
telnet 192.168.1.65 110
```

Resultado:

```bash
Trying 192.168.1.65...
Connected to 192.168.1.65.
Escape character is '^]'.
+OK POP3 server Hombasic-BOF ready <00001.346359@Hombasic-BOF>
USER test
+OK test welcome here
PASS test
-ERR unable to lock mailbox
```

Explicación: Tras tener en ejecución el servicio de **SLMail** en nuestra máquina virtual de Windows 7 de 32 bits (máquina victima). Y comprobar que tenemos comunicación con la máquina víctima (vemos que el puerto 110 - SLMail esta abierto). Usamos `telnet` para conectarnos al servicio SLMail. Introducimos para testear un usuario (USER) y una contraseña (PASS)

---
