
---

# Wfuzz - Uso y Parámetros Útiles

Repositorio oficial: [https://github.com/xmendez/wfuzz](https://github.com/xmendez/wfuzz)

## Parámetros útiles

- `--sl` → Mostrar resultados con un número específico de líneas.
- `--hl` → Ocultar resultados con un número específico de líneas.
- `--sh` → Mostrar resultados con un número específico de caracteres.
- `--hh` → Ocultar resultados con un número específico de caracteres.
- `--sc` → Mostrar respuestas con un código de estado específico.
- `--hc` → Ocultar respuestas con un código de estado específico.
- `--hw` → Ocultar respuestas con un número específico de palabras.
- `--fw <número>` → Mostrar respuestas que tengan exactamente ese número de palabras.
- `-z` → Definir el tipo de payload a utilizar: diccionarios, listas, rangos numéricos, etc.
- `-X` → Usar métodos HTTP personalizados (PUT, DELETE, PATCH, etc.).

---

## Ejemplo con método HTTP personalizado (PUT)

```bash
wfuzz -c -w wordlist.txt -X PUT http://ejemplo.com/FUZZ
````

---

## Enumeración de subdominios modificando la cabecera `Host`

Cuando usamos **Wfuzz** para hacer **fuerza bruta de subdominios**, debemos **modificar la cabecera `Host`** en cada petición.

### Pregunta:

> ¿Qué cabecera debemos usar con Wfuzz si deseamos enumerar subdominios mediante fuerza bruta sobre un dominio dado?

**Respuesta:**

```bash
-H "Host: FUZZ.ejemplo.com"
```

### Ejemplo:

```bash
wfuzz -c -w subdomains.txt -H "Host: FUZZ.ejemplo.com" --hc 400,404,500 http://ejemplo.com
```

### Desglose del comando:

- `-c` → Resultados a color.
    
- `-w subdomains.txt` → Diccionario de subdominios.
    
- `-H "Host: FUZZ.ejemplo.com"` → Sustituye FUZZ por cada subdominio en la cabecera Host.
    
- `--hc 400,404,500` → Oculta errores HTTP comunes.
    
- `http://ejemplo.com` → URL base del servidor objetivo.
    

## Wfuzz para explotar IDOR

```bash
wfuzz -c -X POST -z range,1-1500 -d'pdf_id=FUZZ' http://localhost:5000/download
```

```bash
wfuzz -c -X POST --hl=101,104 -z range,1-1500 -d'pdf_id=FUZZ' http://localhost:5000/download
```

---

## Recomendación

Combina los filtros (`--hc`, `--hl`, `--fw`, etc.) según el patrón de comportamiento del servidor para eliminar el ruido y centrarte en respuestas potencialmente interesantes.

---

 

