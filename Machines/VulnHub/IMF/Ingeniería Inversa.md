
---
# Documentación de funciones vistas en el binario

En el análisis del binario proporcionado, aparecen varias funciones de la librería estándar de C.  
Estas funciones son importantes porque manejan **entrada de usuario**, **comparaciones de cadenas** y **generación de cadenas dinámicas**.  
Vamos a explicarlas en detalle.

---

## fgets()

### Definición
`fgets()` es una función de `stdio.h` que se utiliza para leer texto desde un archivo o desde la entrada estándar (`stdin`).

```c
char *fgets(char *str, int n, FILE *stream);
````

- **`str`** → puntero al buffer donde se almacenará lo leído.
    
- **`n`** → número máximo de caracteres a leer (incluyendo el `\0`).
    
- **`stream`** → origen de lectura, por ejemplo `stdin` para teclado.
    

### Funcionamiento

- Lee hasta `n-1` caracteres o hasta encontrar un salto de línea `\n` o EOF.
    
- Siempre termina la cadena con `\0`.
    
- Devuelve el puntero `str`, o `NULL` si hay error.
    
- Mantiene el `\n` si se encuentra antes de `n-1`.
    

### Ejemplo

```c
char buffer[20];
fgets(buffer, sizeof(buffer), stdin);
```

### Relevancia en el binario

En el binario vemos:

```c
Agent_ID_UserInput = fgets(UserInput, 9, stdin);
```

Aquí:

- Se leen **8 caracteres máximo** del input del usuario (el noveno es para el `\0`).
    
- Se almacena en `UserInput`.
    
- Esto se usa para el **Agent ID**, punto donde el atacante puede introducir datos controlados.
    

---

## strncmp()

### Definición

`strncmp()` es una función de `string.h` que compara **dos cadenas de texto**, pero sólo hasta un número máximo de caracteres.

```c
int strncmp(const char *s1, const char *s2, size_t n);
```

- **`s1` y `s2`** → cadenas a comparar.
    
- **`n`** → número máximo de caracteres a comparar.
    

### Funcionamiento

- Devuelve `0` si son iguales en los primeros `n` caracteres.
    
- Devuelve `< 0` o `> 0` según cuál sea mayor en orden ASCII.
    
- Se detiene al encontrar una diferencia, `\0`, o al llegar a `n`.
    

### Ejemplo

```c
if (strncmp(input, "secreto", 7) == 0) {
    printf("Acceso permitido\n");
}
```

### Relevancia en el binario

El binario usa:

```c
iVar2 = strncmp(UserInput, local_28, 8);
```

- Aquí se compara la entrada del usuario (`UserInput`) con una cadena local (`local_28`).
    
- Si las dos coinciden en los primeros 8 caracteres → el login se valida.
    
- Si no → se muestra `"Invalid Agent ID"`.
    

Esto apunta a que `local_28` contiene la **contraseña o Agent ID válido**.

---

## asprintf()

### Definición

`asprintf()` es una función de GNU (glibc), no estándar de ANSI C, que formatea una cadena en memoria dinámica.

```c
int asprintf(char **strp, const char *fmt, ...);
```

- **`strp`** → dirección de un puntero donde se guardará el buffer creado.
    
- **`fmt`** → cadena de formato (como en `printf`).
    
- **`...`** → valores a insertar en el formato.
    

### Funcionamiento

- Reserva memoria con `malloc()`.
    
- Escribe la cadena formateada en esa memoria.
    
- Devuelve la longitud escrita, o `-1` si falla.
    
- Es necesario liberar la memoria con `free()`.
    

### Ejemplo

```c
char *msg;
asprintf(&msg, "Hola, agente %s", UserInput);
printf("%s\n", msg);
free(msg);
```

### Relevancia en ingeniería inversa

Aunque **no aparece en este fragmento del binario**, puede encontrarse en otras partes. Indica:

- Generación dinámica de cadenas (comandos, rutas, mensajes).
    
- Posibles vulnerabilidades si el formato incluye entrada del usuario.
    
- Uso de memoria dinámica que debemos rastrear en Ghidra.
    

---

## scanf()

### Definición

`scanf()` es una función de la librería estándar de C (`stdio.h`) que se utiliza para leer entrada de datos desde `stdin` y almacenarlos en variables según un formato.

```c
int scanf(const char *format, ...);
```

- **`format`** → cadena de formato que indica el tipo de datos a leer (`%d`, `%s`, `%c`, etc.).
    
- **`...`** → punteros a las variables donde se guardará lo leído.
    

### Funcionamiento

- Lee caracteres desde la entrada estándar (`stdin`).
    
- Los interpreta según los especificadores de formato.
    
- Guarda los valores en las variables pasadas como punteros.
    
- Devuelve el número de valores correctamente leídos.
    

### Ejemplo

```c
int edad;
char nombre[20];

scanf("%d", &edad);
scanf("%19s", nombre);
```

### Problemas de seguridad

- Riesgo de **buffer overflow** si se usa `%s` sin límite, por ejemplo:
    
    ```c
    scanf("%s", nombre); // inseguro
    ```
    
- Mejor práctica: siempre indicar el tamaño máximo menos 1 para dejar espacio al `\0`.
    
    ```c
    scanf("%19s", nombre); // más seguro
    ```
    
- `scanf()` no consume el salto de línea `\n`, lo que puede provocar errores en lecturas posteriores.
    

### Relevancia en ingeniería inversa

En binarios, `scanf()` es crítico porque:

- Es un punto de entrada de datos controlados por el usuario.
    
- Puede derivar en vulnerabilidades como buffer overflow o format string.
    
- En Ghidra, suele aparecer como llamada a `__isoc99_scanf`.
    

---

# Conexión con el binario

El flujo del programa es el siguiente:

## Pseudocódigo simplificado

```c
puts(" |___|_|  |_|_|    System\n");
printf("\nAgent ID : ");

// Leer input del usuario (máx 8 chars)
Agent_ID_UserInput = fgets(UserInput, 9, stdin);

if (Agent_ID_UserInput == NULL) {
    return -1;   // error en lectura
} else {
    // Comparar con la cadena esperada
    if (strncmp(UserInput, local_28, 8) == 0) {
        // Limpiar stdin hasta salto de línea
        do {
            c = getchar();
        } while (c != '\n' && c != EOF);

        puts("Login Validated");

        // Menú principal
        option = menu();

        if (option == 1) {
            extractionpoints();
        } else if (option == 2) {
            requestextraction();
        } else if (option == 3) {
            report();
        } else {
            puts("Exiting...");
        }

        return 0;  // éxito
    } else {
        puts("Invalid Agent ID");
        return -2; // error de login
    }
}
```

---

# Resumen final

1. **fgets()** → lee la entrada del usuario de forma controlada (máx. 8 caracteres).
    
2. **strncmp()** → compara el Agent ID con la cadena interna `local_28`.
    
3. **asprintf()** → genera cadenas dinámicas, aunque no se usa en este fragmento concreto.
    
4. **scanf()** → otra forma de leer entrada del usuario, más propensa a vulnerabilidades si no se controla.
    

El binario implementa una **validación de credenciales simple**, donde conocer el valor de `local_28` es la clave para superar la comprobación inicial.

---


