# GraphQL – Introspection, Mutations e IDORs

## ¿Qué es GraphQL?

GraphQL es un lenguaje de consulta para APIs que nos permite obtener exactamente los datos que necesitamos. A diferencia de las APIs REST tradicionales, que tienen múltiples endpoints, GraphQL expone generalmente un solo endpoint (`/graphql`) y nos permite consultar o modificar datos con una sintaxis declarativa.

Esta flexibilidad también introduce nuevas superficies de ataque que podemos explorar durante una auditoría de seguridad.

---

## Introspection en GraphQL

La introspección es una funcionalidad nativa de GraphQL que permite consultar metadatos del propio esquema de la API. A través de ella podemos descubrir:

- Tipos de datos definidos.
- Queries y Mutations disponibles.
- Relaciones entre entidades.
- Argumentos requeridos y tipos de retorno.

### Ejemplo de consulta de introspección:

```graphql
query {
  __schema {
    types {
      name
      kind
      fields {
        name
      }
    }
  }
}
````

### Riesgos ofensivos

Si la introspección está habilitada en producción, podemos mapear completamente el backend, lo cual facilita:

- Enumerar todos los campos accesibles.
    
- Identificar mutaciones peligrosas.
    
- Encontrar puntos vulnerables a IDOR (Insecure Direct Object Reference).
    
- Entender el flujo de negocio sin necesidad de ingeniería inversa del frontend.
    

---

## Mutations en GraphQL

Las **Mutations** son las operaciones utilizadas para modificar datos dentro de la API. A diferencia de las queries (lectura), las mutaciones permiten:

- Crear registros (`createUser`)
    
- Modificar datos (`updateOrder`)
    
- Eliminar entradas (`deleteComment`)
    

### Ejemplo de Mutación:

```graphql
mutation {
  updateProfile(id: "123", email: "nuevo@mail.com") {
    id
    email
  }
}
```

### Riesgos ofensivos

Si las mutaciones no validan correctamente la identidad del usuario, podemos:

- Modificar recursos que no nos pertenecen.
    
- Realizar acciones maliciosas (DoS, corrupción de datos).
    
- Aprovechar vectores de ataque como IDOR si conocemos identificadores.
    

---

## IDORs en GraphQL

Un **IDOR (Insecure Direct Object Reference)** ocurre cuando podemos acceder o modificar recursos pertenecientes a otros usuarios adivinando o enumerando identificadores.

En GraphQL, esto es especialmente crítico porque:

1. La introspección puede revelar la existencia de recursos y sus IDs.
    
2. Las mutaciones y queries suelen aceptar IDs directamente como argumentos.
    

### Ejemplo de IDOR de lectura:

```graphql
query {
  getOrder(id: "42") {
    id
    user
    total
  }
}
```

Si no existe validación de que el ID "42" pertenece a nuestra cuenta, podemos acceder a pedidos de otros usuarios.

### Ejemplo de IDOR de modificación:

```graphql
mutation {
  updateOrder(id: "42", total: 0) {
    id
    total
  }
}
```

Podemos alterar pedidos de otros usuarios sin autorización, causando daño financiero o sabotaje de datos.

---

## Flujo de explotación ofensivo

1. **Descubrimiento del endpoint `/graphql`.**
    
2. **Ejecutamos introspección para mapear el esquema.**
    
3. **Identificamos mutaciones o queries sensibles (getUser, updateProfile, etc).**
    
4. **Adivinamos o forzamos IDs usando numeración incremental.**
    
5. **Probamos acceso no autorizado a recursos (lectura o modificación).**
    

---

## Medidas defensivas (para entender qué debemos romper)

- Deshabilitar introspección en entornos de producción.
    
- Implementar controles de autorización en backend, no confiar solo en el frontend.
    
- Validar que los IDs usados en queries/mutations pertenecen al usuario autenticado.
    
- Usar UUIDs en lugar de IDs incrementales para dificultar la enumeración.
    

---

## Conclusión

GraphQL es poderoso pero expone mucha información si no se configura correctamente. Podemos explotar su introspección para mapear el backend, utilizar mutaciones para modificar recursos, y explotar IDORs para acceder a objetos ajenos. Durante un pentest, es esencial auditar exhaustivamente el endpoint GraphQL en busca de estas debilidades.

---
