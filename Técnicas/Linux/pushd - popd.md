
--- 

# Uso de `pushd` y `popd` en la terminal


## ¿Qué es `pushd`?

> Cuando trabajamos en la terminal, muchas veces necesitamos movernos entre distintos directorios. El comando `pushd` nos permite cambiar de directorio **guardando al mismo tiempo el directorio actual**. Así, luego podemos volver fácilmente con `popd`.

---

## ¿Qué hace `pushd /var/www/html`?

```
pushd /var/www/html
```

Este comando realiza dos acciones:

1. Cambia al directorio `/var/www/html`.
2. Guarda el directorio en el que estábamos anteriormente en una **pila de directorios** (stack).

---

## ¿Qué hacemos luego con `popd`?

Cuando queremos volver al directorio anterior, usamos:

```
popd
```

Esto nos regresa automáticamente al directorio que guardamos con `pushd`, sin tener que recordar la ruta completa.

---

## Ejemplo práctico

Supongamos que estamos en:

```
~/Escritorio/GramsciXI/OWASP/LFI
```

Y ejecutamos:
```
pushd /var/www/html
```

Ahora estamos en `/var/www/html`, pero el sistema recuerda que antes estábamos en `~/Escritorio/GramsciXI/OWASP/LFI`.

Si luego hacemos:
```
popd
```

Volvemos directamente al directorio original.

---

## ¿Por qué usar `pushd` y `popd` en lugar de `cd`?

| Comando   | Acción                                                   |
|-----------|----------------------------------------------------------|
| `cd`      | Cambia de directorio sin guardar historial.              |
| `pushd`   | Cambia de directorio y guarda el actual.                 |
| `popd`    | Vuelve al último directorio guardado con `pushd`.        |

Esto es especialmente útil cuando automatizamos tareas con scripts o cuando trabajamos entre varios directorios y no queremos escribir las rutas a mano cada vez.

---

## Conclusión

`pushd` y `popd` son herramientas muy útiles que nos permiten ahorrar tiempo y mantener un flujo de trabajo más organizado cuando trabajamos en entornos de desarrollo o pruebas de seguridad.

---
