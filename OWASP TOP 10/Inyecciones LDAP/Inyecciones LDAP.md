# Inyección LDAP (Lightweight Directory Access Protocol)

Las **inyecciones LDAP** son un tipo de ataque que nos encontramos cuando una aplicación web interactúa con un servidor **LDAP** sin validar correctamente los datos introducidos por los usuarios. Este servidor LDAP actúa como un directorio centralizado donde se almacena información crítica de usuarios, grupos y otros recursos de red.

## ¿Cómo funciona una inyección LDAP?

Una inyección LDAP se produce cuando introducimos comandos **LDAP maliciosos** en un campo de entrada (por ejemplo, un formulario de login), y estos comandos son enviados directamente al servidor LDAP. Si la aplicación no filtra ni valida esos datos, podríamos manipular las consultas internas al directorio.

Esto es muy similar a las inyecciones SQL: el objetivo es manipular una consulta para alterar su comportamiento previsto.

---

## ¿Qué puede lograr un atacante?

Con una inyección LDAP exitosa, un atacante podría:

-  Acceder a datos sensibles de usuarios o recursos.
-  Modificar registros: añadir, eliminar o alterar usuarios o atributos del directorio.
-  Realizar movimientos laterales dentro de la red o preparar ataques de phishing.
-  Insertar software malicioso en los sistemas conectados al directorio.

---

##  ¿Cómo prevenimos las inyecciones LDAP?

Para proteger nuestras aplicaciones de este tipo de ataques, debemos seguir buenas prácticas:

-  Validar la entrada del usuario: asegurarnos de que cumple con el formato esperado.
-  Escapar caracteres especiales: como `*`, `(`, `)`, `&`, `|`, `=`, etc.
-  Evitar la concatenación directa en las consultas LDAP.
-  Ejecutar la aplicación con privilegios mínimos.
-  Monitorizar el servidor LDAP ante comportamientos sospechosos.

---

##  Ejemplo práctico (entorno de laboratorio)

Podemos practicar esta vulnerabilidad de forma segura utilizando el siguiente repositorio:

**LDAP-Injection-Vuln-App**: https://github.com/motikan2010/LDAP-Injection-Vuln-App

###  ¿Qué haremos?
1. Clonamos el repositorio y levantamos el entorno con Docker.
2. Accedemos al formulario de login de la aplicación vulnerable.
3. Introducimos entradas maliciosas para evadir el login o consultar información adicional.

#### Ejemplo de payload:
```

username=_)(uid=_))(|(uid=*  
password=cualquiervalor

```

Este tipo de entrada puede permitirnos **bypassear la autenticación** si la aplicación concatena directamente los datos en la consulta LDAP.

---

##  Caso real: Inyección LDAP en Active Directory (Microsoft)

Un caso real documentado ocurrió en aplicaciones internas de grandes organizaciones que usaban **Active Directory** para gestionar accesos. Un atacante descubrió que el portal de login concatenaba directamente el nombre de usuario con la consulta LDAP sin ninguna validación.

**Resultado:** El atacante consiguió autenticarse como cualquier usuario sin conocer su contraseña, obteniendo acceso privilegiado a la red interna. Desde ahí, pudo moverse lateralmente y escalar privilegios.

Este tipo de fallo en un entorno real puede ser devastador, especialmente cuando el servidor LDAP forma parte de la infraestructura crítica.

---

##  Conclusión

Las inyecciones LDAP son menos conocidas que las SQL, pero igual de peligrosas. Como profesionales en formación, debemos practicar con entornos controlados y entender cómo proteger nuestras aplicaciones desde el diseño. La validación y sanitización de entradas nunca debe subestimarse.

---

# Búsqueda en servidor LDAP con `ldapsearch`

## Paso: Realizamos una búsqueda LDAP como administrador

### Acción
Ejecutamos el siguiente comando para buscar en el servidor LDAP local la entrada cuyo `cn` (Common Name) sea igual a `admin`:

```bash
ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D "cn=admin,dc=example,dc=org" -w admin 'cn=admin'
````

---

### Explicación

- `ldapsearch`: herramienta de línea de comandos para hacer búsquedas en LDAP.
    
- `-x`: usamos autenticación simple.
    
- `-H ldap://localhost`: nos conectamos al servidor LDAP en `localhost`.
    
- `-b dc=example,dc=org`: indicamos la base de búsqueda del árbol LDAP.
    
- `-D "cn=admin,dc=example,dc=org"`: nos autenticamos como el usuario administrador.
    
- `-w admin`: usamos la contraseña del administrador.
    
- `'cn=admin'`: filtro que busca entradas con `cn=admin`.
    

Este comando busca cualquier entrada LDAP que coincida con ese filtro, dentro del árbol con base `dc=example,dc=org`.

---

### Resultado obtenido

```ldif
# extended LDIF
#
# LDAPv3
# base <dc=example,dc=org> with scope subtree
# filter: cn=admin
# requesting: ALL
#

# admin, example.org
dn: cn=admin,dc=example,dc=org
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator
userPassword:: e1NTSEF9R3JpbzFjZTcwYXBmaVY3NzVkSlgwS0JOZVFzWGU1cUg=

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

---

### Análisis del resultado

-  **Resultado exitoso** (`result: 0 Success`).
    
-  Se encontró **1 entrada LDAP** con `cn=admin`.
    
-  El campo `userPassword` aparece cifrado (base64 + hash).
    
    - El valor `e1NTSEF9...` es un hash **SSHA (Salted SHA-1)** codificado en base64.
        
    - Puede ser útil para **ataques de cracking offline** si logramos extraerlo.
        

---

## Conclusión

Hemos conseguido consultar correctamente un servidor LDAP autenticándonos como administrador. Este tipo de consulta es clave para:

- Enumerar usuarios o roles en un entorno comprometido.
    
- Obtener información sensible como hashes de contraseñas.
    
- Evaluar la exposición del servidor LDAP ante accesos externos.
    

---

Acción:

```bash
cat new-user.ldif 
```

Resultado:

```bash
dn: uid=billy,dc=example,dc=org
uid: billy
cn: billy
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/billy
uidNumber: 14583102
gidNumber: 14564100
userPassword: {SSHA}j3lBh1Seqe4rqF1+NuWmjhvtAni1JC5A
mail: billy@example.org
```

Explicación: estructura básica de un usuario LDAP

Acción:

```bash
nvim newuser.ldif
```

Resultado: 

```lua
dn: uid=Metahumo,dc=example,dc=org
uid: Metahumo
cn: billy
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/Metahumo
uidNumber: 14583102
gidNumber: 14564100
userPassword: Metahumo123
mail: metahumo@mail.com
description: Hacker
telephoneNumber: 666111333
```

Acción:

```bash
ldapadd -x -H ldap://localhost -D "cn=admin,dc=example,dc=org" -w admin -f newuser.ldif
```

Resultado:

```bash
adding new entry "uid=Metahumo,dc=example,dc=org"
```

Explicación: hemos añadido un nuevo usuario 

Acción:

```bash
ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D "cn=admin,dc=example,dc=org" -w admin
```


Resultado:

```bash
...
# Metahumo, example.org
dn: uid=Metahumo,dc=example,dc=org
uid: Metahumo
cn: billy
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/Metahumo
uidNumber: 14583102
gidNumber: 14564100
userPassword:: TWV0YWh1bW8xMjM=
mail: metahumo@mail.com
description: Hacker
telephoneNumber: 666111333

# search result
search: 2
result: 0 Success

# numResponses: 4
# numEntries: 3
```


Acción:

```bash
ldapmodify -x -H ldap://localhost -D "cn=admin,dc=example,dc=org" -w admin -f newuser.ldif
```

Explicación: este último comando es para modificar datos de usuarios ya existentes
