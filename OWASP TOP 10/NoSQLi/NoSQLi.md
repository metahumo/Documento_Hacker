# Inyección NoSQL: Explicación y Casos Prácticos

## Introducción

Las inyecciones NoSQL son una vulnerabilidad común en aplicaciones web que utilizan bases de datos NoSQL como MongoDB, Cassandra o CouchDB. Esta vulnerabilidad ocurre cuando la aplicación permite que un atacante introduzca datos maliciosos en una consulta, sin validar o sanitizar adecuadamente dichos datos.

Aunque el funcionamiento recuerda a las inyecciones SQL, en este caso el objetivo son bases de datos que no usan un modelo relacional, sino que almacenan datos en documentos o estructuras flexibles. Las inyecciones NoSQL permiten manipular consultas de forma inesperada para el servidor, lo que puede dar lugar a la extracción de datos confidenciales, la omisión de autenticaciones o incluso la modificación de datos.

---

## ¿Cómo funciona?

Las bases de datos NoSQL, especialmente MongoDB, suelen utilizar objetos JSON para realizar consultas. Si no se filtran correctamente los datos que introduce el usuario, podemos inyectar estructuras maliciosas como operadores de MongoDB (`$ne`, `$gt`, `$or`, etc.) y alterar la lógica de la consulta.

Esto puede permitirnos, por ejemplo:

- Saltarnos la autenticación sin conocer usuario ni contraseña.
- Acceder a datos sensibles de otros usuarios.
- Insertar o eliminar registros sin autorización.

---

## Caso práctico: Explotación en una app vulnerable (Vulnerable-Node-App)

Para practicar este tipo de vulnerabilidad, utilizamos la siguiente aplicación vulnerable alojada en GitHub:

**Repositorio:** [Vulnerable-Node-App](https://github.com/Charlie-belmer/vulnerable-node-app)

### 1. Preparación del entorno

Clonamos el repositorio y levantamos el entorno con Docker:

```bash
git clone https://github.com/Charlie-belmer/vulnerable-node-app
cd vulnerable-node-app
docker-compose up -d
````

La aplicación se levanta en el puerto `3000`.

### 2. Exploración de la app

Accedemos a `http://localhost:4000` y vemos que hay un formulario de inicio de sesión con campos de usuario y contraseña. Probamos con credenciales válidas y fallidas para entender su funcionamiento.

### 3. Inyección NoSQL en el login

Intentamos autenticarnos con el siguiente payload:

```json
usuario: {"$ne": null}
contraseña: {"$ne": null}
```

En la interfaz, esto se traduce a:

```
Username: {"$ne": null}
Password: {"$ne": null}
```

El backend interpreta esta entrada como una consulta donde el nombre de usuario y la contraseña **no sean nulos**, lo cual es siempre verdadero para al menos un usuario de la base de datos. Resultado: conseguimos autenticarnos sin conocer credenciales válidas.

### 4. Explicación

En MongoDB, el operador `$ne` significa "distinto de". Al inyectarlo como valor en el JSON, la consulta pasa a ser:

```javascript
db.users.findOne({ usuario: { $ne: null }, contraseña: { $ne: null } })
```

Este tipo de ataque es posible porque el backend espera una cadena de texto, pero nosotros le enviamos un objeto JSON con una estructura válida para MongoDB.

---

## Caso real: Inyección NoSQL en la aplicación de chat de HackingTeam (2015)

Durante la filtración de datos de HackingTeam en 2015, se descubrió una aplicación de mensajería interna vulnerable a inyecciones NoSQL. La aplicación usaba MongoDB para gestionar usuarios y mensajes. Un atacante fue capaz de explotar la lógica de autenticación al enviar un JSON malicioso como entrada.

Al inyectar una estructura como:

```json
{
  "username": { "$ne": null },
  "password": { "$ne": null }
}
```

se logró evadir el inicio de sesión. Esto permitió el acceso a conversaciones internas, datos de empleados y documentos sensibles sin necesidad de tener credenciales reales.

Este caso demostró cómo la falta de validación en aplicaciones modernas puede tener consecuencias críticas, incluso en empresas que se dedican a servicios de ciberseguridad.

---

## Conclusión

La inyección NoSQL es una amenaza real que puede comprometer seriamente la seguridad de las aplicaciones web modernas. Para prevenirla, debemos:

- Validar y sanitizar todas las entradas del usuario.
    
- Usar consultas parametrizadas cuando sea posible.
    
- Implementar controles de autenticación y autorización robustos.
    

Como práctica, recomendamos revisar el código fuente de las aplicaciones y entender cómo se construyen las consultas a la base de datos. Cuanto más entendamos la lógica del backend, más fácil será identificar puntos vulnerables.

---

