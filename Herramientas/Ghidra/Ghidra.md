
# Ghidra: Instalación y Uso Básico

## ¿Qué es Ghidra?

**Ghidra** es una herramienta de ingeniería inversa desarrollada por la **NSA** (Agencia de Seguridad Nacional de EE. UU.). Permite **analizar binarios compilados** de diferentes arquitecturas y plataformas, desensamblarlos y descompilarlos a un lenguaje de más alto nivel.

Ghidra es útil para tareas como:

- Análisis de malware
- Ingeniería inversa de software propietario
- Descubrimiento de vulnerabilidades (como Buffer Overflows)
- Estudio de técnicas anti-debugging y ofuscación

Es software libre, multiplataforma (Windows, Linux, macOS) y soporta múltiples arquitecturas (x86, x64, ARM, MIPS, etc.).

---

## Requisitos Previos

- Tener instalado **Java 17+ (JDK)**.
- Sistema operativo: Windows, Linux o macOS.
- Se recomienda al menos 4 GB de RAM (idealmente más).

---

## Instalación

### 1. Descargar Ghidra

Accede al repositorio oficial:  
- https://github.com/NationalSecurityAgency/ghidra

También puedes descargar directamente desde:  
- https://ghidra-sre.org/

### 2. Extraer el contenido

Una vez descargado el `.zip`, descomprímelo en la carpeta que prefieras:

```bash
unzip ghidra_10.X.X_PUBLIC_*.zip -d ~/tools/
cd ~/tools/ghidra_10.X.X_PUBLIC/
````

### 3. Verificar Java

Ghidra necesita Java 17 o superior. Puedes instalarlo así:

#### En Debian/Ubuntu:

```bash
sudo apt update
sudo apt install openjdk-17-jdk
```

Verifica que Java está funcionando:

```bash
java -version
```

---

## Ejecución

Para ejecutar Ghidra, basta con lanzar el siguiente script:

```bash
./ghidraRun
```

Esto abrirá la interfaz gráfica de usuario (GUI) de Ghidra.

---

## Uso Básico

### 1. Crear un nuevo proyecto

- Elige **"File" > "New Project"**
    
- Selecciona **Non-Shared Project**
    
- Ponle un nombre y elige la carpeta donde se guardará.
    

### 2. Importar un binario

- Haz clic derecho en el proyecto o usa **"File" > "Import File"**
    
- Selecciona el binario (por ejemplo, `/usr/local/bin/agent`)
    
- Ghidra detectará automáticamente el tipo de archivo (ELF, PE, etc.)
    

### 3. Analizar el binario

- Una vez importado, ábrelo haciendo doble clic.
    
- Se lanzará el **Analyzer**, que te pedirá opciones (puedes dejarlas por defecto al principio).
    
- Espera a que finalice el análisis.
    

### 4. Navegar el binario

- **Symbol Tree**: muestra funciones detectadas, strings, imports, etc.
    
- **Listing**: código desensamblado en ASM.
    
- **Decompiler**: código decompilado en pseudocódigo C.
    
- Puedes marcar funciones, cambiar nombres, añadir comentarios, etc.
    

---

## Consejos para el análisis

- Usa `Search > For Strings` para localizar posibles mensajes o funciones sospechosas.
    
- Usa `Function Graph` para visualizar el flujo lógico de una función.
    
- Marca offsets importantes si estás analizando una vulnerabilidad específica.
    

---

## Recursos adicionales

- Documentación oficial: [https://ghidra-sre.org/Documentation.html](https://ghidra-sre.org/Documentation.html)
    
- Curso gratuito de ingeniería inversa con Ghidra:  
    [https://www.opensecuritytraining.info/](https://www.opensecuritytraining.info/)
    
- Cheat sheet de atajos:  
    [https://github.com/0xdea/ghidra-cheatsheet](https://github.com/0xdea/ghidra-cheatsheet)
    

---

## Conclusión

Ghidra es una herramienta fundamental para la ingeniería inversa y el análisis de binarios. A diferencia de otras herramientas como IDA Pro, Ghidra es completamente libre y de código abierto, lo cual la hace ideal para quienes están aprendiendo sobre vulnerabilidades en ejecutables.

En el contexto de escaladas de privilegios o explotación binaria (como BOF), nos permite entender la lógica interna de un binario potencialmente vulnerable y desarrollar exploits más precisos.

---
