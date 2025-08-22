
---
# Vulnerabilidad Shellshock: Versiones afectadas de Bash

La vulnerabilidad **Shellshock** afecta al intérprete de comandos **Bash** en versiones que van desde las muy antiguas (1.x) hasta la versión 4.3 sin parchear. Fue descubierta en septiembre de 2014 y se catalogó bajo el identificador **CVE-2014-6271**, aunque posteriormente se detectaron variantes adicionales.

---

## ¿Qué versiones de Bash están afectadas?

- Todas las versiones **desde Bash 1.14 (1994)** hasta **Bash 4.3**, **sin parches**.
- **Dentro de Bash 4.3**, están afectadas todas las versiones **anteriores al parche `bash43-025`**.

La vulnerabilidad radica en la forma en que Bash maneja funciones definidas en variables de entorno. Esta mala gestión permite la ejecución de comandos arbitrarios si un atacante logra inyectarlos en variables como `User-Agent`, `Referer`, `Cookie`, etc.

---

## ¿Qué versión corrige la vulnerabilidad Shellshock?

- La **versión corregida** es Bash **4.3 con el parche `bash43-025`**.
- Las versiones **posteriores a Bash 4.3 parcheado**, como **4.4, 5.0 y superiores**, no son vulnerables.

Además, después del descubrimiento original (CVE-2014-6271), se identificaron más vulnerabilidades relacionadas:

- CVE-2014-7169
- CVE-2014-7186
- CVE-2014-7187
- CVE-2014-6278, entre otras

Por ello, se recomienda mantener Bash **completamente actualizado**.

---

## Tabla de resumen

| Versión de Bash         | ¿Vulnerable? |
|-------------------------|--------------|
| < 4.3 (sin parches)     | ✅ Sí         |
| 4.3 (sin `bash43-025`)  | ✅ Sí         |
| 4.3-patched (con `bash43-025` o superior) | ❌ No        |
| >= 4.4                  | ❌ No         |

---

## ¿Cómo comprobar si un sistema es vulnerable?

### 1. Comprobar la versión instalada:

```bash
bash --version
````

### 2. Realizar una prueba segura:

```bash
env x='() { :;}; echo VULNERABLE' bash -c "echo prueba"
```

- Si el sistema es vulnerable, imprimirá algo como:
    
    ```
    VULNERABLE
    prueba
    ```
    
- Si el sistema está parcheado, imprimirá solo:
    
    ```
    prueba
    ```
    

---

## Recomendaciones

- **Actualizar Bash** a la última versión disponible mediante el gestor de paquetes del sistema.
    
- **Desactivar CGI** o usar lenguajes que no dependan de Bash para interpretar scripts.
    
- **Monitorizar las cabeceras HTTP** que se reciben en servicios públicos o accesibles desde el exterior.
    
- **Aplicar controles de seguridad perimetrales** para prevenir la inyección de variables maliciosas.
    

---
