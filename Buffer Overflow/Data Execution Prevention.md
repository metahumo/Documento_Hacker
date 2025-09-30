
---

# Data Execution Prevention (DEP) en Windows 7

## ¿Qué es DEP?

Según Microsoft:

> **Data Execution Prevention (DEP)** es una característica de seguridad que ayuda a evitar daños en el equipo provocados por virus u otras amenazas.  Algunos programas maliciosos intentan ejecutar código desde zonas de la memoria que están reservadas para Windows y aplicaciones autorizadas. Este tipo de ataques pueden comprometer archivos y programas.

DEP protege el sistema vigilando cómo los programas utilizan la memoria.  
Si detecta que un programa intenta ejecutar código de manera incorrecta, lo bloquea y muestra una notificación.

---

## ¿Por qué desactivar DEP?

- Puede provocar bloqueos en aplicaciones legítimas.  
  Ejemplo: en versiones antiguas de **Firefox**, al abrir ciertos servicios en múltiples pestañas (como YouTube), el navegador podía cerrarse de forma inesperada debido a DEP.

- Algunos ejecutables que necesitan acceder directamente a la memoria del sistema no se pueden instalar o ejecutar mientras DEP está activado.

>  Nota: Se recomienda desactivar DEP **solo** si es estrictamente necesario (por ejemplo, para instalar un ejecutable legítimo que no se ejecute de otra forma o para entornos de laboratorio donde queramos ejecutar exploits de *buffer overflow*).

---

## Métodos para desactivar DEP

### 1. Desde la interfaz gráfica

1. Ir a **Inicio** → clic derecho en **Equipo** → **Propiedades**.  
2. En la ventana de Sistema, seleccionar **Configuración avanzada del sistema**.  
3. En **Propiedades del sistema**, dentro de **Rendimiento**, hacer clic en **Configuración**.  
4. En **Opciones de rendimiento**, pestaña **Prevención de ejecución de datos (DEP)**, marcar:  
   - *"Activar DEP para todos los programas y servicios, excepto los que seleccione:"*  
5. Pulsar en **Agregar** y elegir el archivo ejecutable al que queremos desactivar DEP.

---

### 2. Desde la línea de comandos (desactivación completa)

>  Solo usar si se es administrador y entendemos los riesgos.

1. Abrir **Símbolo del sistema** como Administrador.
2. Ejecutar los siguientes comandos:

- Para desactivar DEP por completo:
  ```bash
  bcdedit.exe /set {current} nx AlwaysOff
```

- Para volver a activarlo:
    
    ```bash
    bcdedit.exe /set {current} nx AlwaysOn
    ```
    
- Para deshabilitarlo de manera global (sin `{current}`):
    
    ```bash
    bcdedit.exe /set nx AlwaysOff
    ```
    
- Para habilitarlo de manera global:
    
    ```bash
    bcdedit.exe /set nx AlwaysOn
    ```
    

---

## Configuraciones adicionales con `bcdedit`

- **OptIn**  
    Activa DEP solo para los componentes del sistema operativo (kernel y drivers).
    
    ```bash
    bcdedit.exe /set nx OptIn
    ```
    
- **OptOut**  
    Activa DEP para el sistema operativo y todos los procesos, pero permite desactivarlo manualmente para programas concretos desde el Panel de Control.
    
    ```bash
    bcdedit.exe /set nx OptOut
    ```
    

---

## Recomendación

- Primero, probar con el **método gráfico** (desactivar DEP solo para programas concretos).
    
- Usar el **método de línea de comandos** únicamente si tenemos experiencia y necesitamos desactivar DEP globalmente (ejemplo: pruebas de _exploits_ en un laboratorio controlado).
    

---

## Relación con el Buffer Overflow en Windows 7

En entornos con **DEP activado**, un _buffer overflow_ que inyecta _shellcode_ directamente en la pila (stack) o en el heap no funcionará, ya que Windows marcará esas zonas de memoria como **no ejecutables**.  
Por eso, para poder realizar pruebas en un laboratorio de explotación en Windows 7, muchas veces se requiere **desactivar DEP**, o bien emplear técnicas más avanzadas como **ROP (Return Oriented Programming)** que permiten saltarse DEP sin deshabilitarlo.


---
