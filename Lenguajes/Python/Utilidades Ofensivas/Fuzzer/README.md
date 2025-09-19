
---

# Fuzzer — PoC - Tutorial 

Repositorio con la evolución de un **fuzzer** para descubrimiento de endpoints y subdominios (PoC educativo). 

El objetivo ha sido construir paso a paso un prototipo que vaya incorporando funcionalidades útiles para pentesting web: wordlists, subdominios, recursividad, control de ruido, filtros anti-falsos positivos, múltiples métodos HTTP, headers personalizados y logging.

> **Estado:** Prototipos finalizados hasta `v4` (script `fuzzer.py`).  
> Estos scripts son **pruebas / PoC** para entornos controlados y con permiso del propietario del objetivo.

---

## ¿Qué hay en este repositorio?

Se incluyen (entre otros) los siguientes scripts/prototipos que documentan la evolución:

- `fuzzer_v1.py` — primer script mínimo (GET simple).
- `fuzzer_v2.py` — argparse para URL, función `fuzzer`.
- `fuzzer_v3.py` / `fuzzer_v4.py` — wordlists, validación de archivos, filtrado de códigos.
- `fuzzer_v2.1.py`, `fuzzer_v2.2.py`, `fuzzer_v2.3.py` — mejoras intermedias (opciones, subdominios, handler SIGINT).
- `fuzzer_prototipo_v3.py` — primer prototipo recursivo (endpoints + subdominios).
- **`fuzzer_v3.1.py`** — versión con hashing y mejoras anti-falsos-positivos.
- **`fuzzer_v3.2.py`** — versión avanzada con logging, métodos HTTP y más (prototipo).
- **`fuzzer_v4.py`** — versión final del PoC: añade `-H` (headers) y `-d` (data) además de todo lo anterior.

> Consulta los ficheros en este repositorio para ver el código completo de cada versión y el `fuzzer_PoC_tutorial.md` para la documentación detallada.

---

## Requisitos / Instalación

Este script usa Python 3 y la librería `requests`.

1. Clona el repositorio (o descarga el archivo `fuzzer.py`):

```bash
git clone https://github.com/metahumo/Documento_Hacker.git
cd Documento_Hacker/Lenguajes/Python/Utilidades\ Ofensivas/Fuzzer/Script/
python3 fuzzer.py --help

# con curl
curl -L -o fuzzer.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/Lenguajes/Python/Utilidades%20Ofensivas/Fuzzer/Script/fuzzer.py"

# con wget
wget -O fuzzer.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/Lenguajes/Python/Utilidades%20Ofensivas/Fuzzer/Script/fuzzer.py"

````

2. Instala dependencias:

```bash
python3 -m pip install --user requests
```

(En entornos virtuales: crea y activa `venv` y luego `pip install requests`).

---

## Uso básico

```bash
# Ejemplo mínimo (endpoints desde endpoints.txt)
python3 fuzzer_v3.3.py http://objetivo.com -e endpoints.txt

# Usando wordlist combinada (endpoints + subdominios)
python3 fuzzer_v3.3.py http://objetivo.com -w combined_wordlist.txt

# Ajustando tiempo entre peticiones (delay) y profundidad
python3 fuzzer_v3.3.py http://objetivo.com -w combined.txt -t 1.5 --max-depth 2

# Probar múltiples métodos HTTP y enviar data para POST
python3 fuzzer_v3.3.py http://objetivo.com -e endpoints.txt -m GET HEAD POST -d "username=admin&password=1234"

# Añadir headers personalizados (por ejemplo User-Agent y X-Forwarded-For)
python3 fuzzer_v3.3.py http://objetivo.com -e endpoints.txt -H "User-Agent: CustomScanner/1.0" -H "X-Forwarded-For: 1.2.3.4"
```

El script imprimirá en tiempo real los endpoints/subdominios "interesantes" y guardará un log con nombre `fuzzer_log_YYYYMMDD_HHMMSS.txt`.

---

## Tabla de parámetros (resumen)

| Parámetro          | Descripción                                          | Ejemplo                                               |
| ------------------ | ---------------------------------------------------- | ----------------------------------------------------- |
| `url`              | URL objetivo (obligatorio)                           | `http://objetivo.com`                                 |
| `-e, --endpoints`  | Wordlist de endpoints                                | `-e endpoints.txt`                                    |
| `-s, --subdomains` | Wordlist de subdominios                              | `-s subdomains.txt`                                   |
| `-w, --wordlist`   | Wordlist combinada (dominios + subdominios)          | `-w combined.txt`                                     |
| `-t, --time`       | Tiempo entre peticiones (segundos, puede ser float)  | `-t 1.5`                                              |
| `--max-depth`      | Profundidad máxima recursiva (entero)                | `--max-depth 3`                                       |
| `-m, --methods`    | Métodos HTTP a usar (lista)                          | `-m GET HEAD POST`                                    |
| `-d, --data`       | Datos para métodos con cuerpo (POST/PUT)             | `-d "username=admin&password=1234"`                   |
| `-H, --header`     | Headers personalizados (varios `-H "Header: Valor"`) | `-H "User-Agent: Custom/1.0" -H "X-Fwd-For: 1.2.3.4"` |

---

## Qué hace el script final (`fuzzer_v3.3.py`)

Breve resumen:

* Prueba endpoints y/o subdominios a partir de wordlists (`-e`, `-s`, `-w`).
* Soporta múltiples métodos HTTP (`-m`) y envío de datos (`-d`) para POST/PUT.
* Soporta headers personalizados (`-H`), útil para cambiar `User-Agent` o añadir cabeceras específicas.
* Filtra resultados mostrando solo códigos "interesantes" (por defecto: 200, 301, 302, 403).
* Reduce falsos positivos comparando hash del contenido de la respuesta.
* Ejecuta búsquedas recursivas controladas por `--max-depth`.
* Añade un `delay` aleatorio controlable con `-t` para reducir la posibilidad de detección.
* Genera un log con fecha/hora con todos los resultados.

---

## Buenas prácticas y advertencias

* **Solo prueba objetivos para los que tengas permiso explícito**. Ejecutar scans en sistemas sin autorización puede ser ilegal.
* Empieza con `-t 1` o `-t 2` en objetivos en producción para reducir ruido.
* Ajusta `--max-depth` para controlar el alcance y tiempo de ejecución.
* Revisa el log generado para análisis posterior.
* Ten en cuenta que algunos WAFs/WAF rules u IDS/IPS pueden bloquear peticiones aunque uses `-t` y `User-Agent` realista.

---

## Licencia y atribución

Este repositorio contiene material de aprendizaje y pruebas. Úsalo bajo tu propia responsabilidad y respeta las leyes y políticas de uso de los sistemas objetivo. Puedes adaptar el código para tus propios fines educativos o de pentesting autorizado.

---
