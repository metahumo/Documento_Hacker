
---
# Python – Ataque de Deserialización YAML (DES-YAML)

## ¿Qué es un Ataque de Deserialización YAML?

Un **Ataque de Deserialización YAML** (DES-YAML) es una vulnerabilidad que ocurre cuando una aplicación en Python deserializa datos YAML que provienen de una fuente no confiable, sin realizar controles de seguridad adecuados.

YAML (Yet Another Markup Language) es un formato de serialización de datos ampliamente utilizado por su simplicidad. Sin embargo, las funciones de deserialización como `yaml.load()` pueden representar un grave riesgo si se usan sin precauciones.

## ¿Cómo se explota?

Cuando una aplicación utiliza `yaml.load()` en lugar de `yaml.safe_load()` para procesar la entrada, es posible ejecutar código arbitrario si el atacante tiene control sobre el contenido del archivo o cadena YAML. Esto es porque `yaml.load()` permite la construcción de objetos arbitrarios de Python, incluyendo clases como `os.system`.

### Ejemplo de código vulnerable:

```python
import yaml

data = """
!!python/object/apply:os.system ["echo Pwned desde YAML!"]
"""

yaml.load(data, Loader=yaml.FullLoader)  # ¡Vulnerable!
````

Este código ejecuta el comando `echo Pwned desde YAML!` en el sistema.

### Solución segura:

```python
import yaml

yaml.safe_load(data)  # No ejecuta código arbitrario
```

## Riesgos

- **Ejecución remota de código (RCE)**.
    
- **Acceso a información sensible**.
    
- **Denegación de servicio (DoS)**.
    
- **Escalada de privilegios (si la app corre como root)**.
    

## Mitigaciones

- Usar siempre `yaml.safe_load()` en lugar de `yaml.load()` salvo que sepas exactamente lo que haces.
    
- No procesar entradas YAML directamente desde el usuario.
    
- Aplicar validación estricta y sanitización.
    
- Ejecutar deserializaciones en entornos limitados (sandboxing).
    

---

## Ejemplo práctico

Archivo `payload.yaml` malicioso:

```yaml
!!python/object/apply:subprocess.check_output
- ["id"]
```

Código vulnerable:

```python
import yaml

with open("payload.yaml") as f:
    data = yaml.load(f, Loader=yaml.FullLoader)
    print(data.decode())
```

Este código ejecutará `id` en el sistema, devolviendo información del usuario actual, lo que confirma la ejecución arbitraria.

## Caso real

En 2017, investigadores descubrieron una vulnerabilidad en una herramienta de automatización escrita en Python que permitía cargar configuraciones desde archivos YAML sin validar su origen ni el contenido. Mediante un archivo YAML manipulado, lograron ejecutar comandos en el servidor, obteniendo una shell remota. La causa fue el uso de `yaml.load()` sin restricción alguna.

---

## Conclusión

Las deserializaciones inseguras son una fuente crítica de vulnerabilidades. En Python, cuando se trabaja con YAML, debemos tratar todos los datos de entrada como no confiables y optar siempre por `safe_load()`. Como pentesters, debemos analizar rutas que procesen archivos de configuración o entradas del usuario que se deserializan automáticamente para detectar vectores de RCE.

---
