
---

# Guía de Hardening de Docker

En esta guía vamos a aprender cómo reforzar la seguridad de un entorno Docker, aplicando medidas preventivas que reduzcan la superficie de ataque. Nuestro objetivo es minimizar el impacto que podría tener una mala configuración o una vulnerabilidad en contenedores en ejecución.

## 1. No usar `--privileged` innecesariamente

El flag `--privileged` otorga acceso completo al host, lo cual es extremadamente peligroso. En su lugar, debemos usar `--cap-add` y `--cap-drop` para controlar exactamente qué capacidades necesita un contenedor.

### Ejemplo:

```bash
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE -it nginx
```

Aquí eliminamos todas las capacidades excepto la que permite bindear puertos <1024.

---

## 2. Evitar la exposición del socket Docker (`/var/run/docker.sock`)

Montar el socket Docker en un contenedor le da control total sobre el host.

### No hacer:

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock -it someimage
```

En su lugar, si necesitamos control limitado, usar una API proxy controlada o `docker-slim`.

---

## 3. No exponer la API en el puerto 2375 sin TLS

El demonio de Docker puede configurarse para aceptar conexiones TCP, pero nunca debe hacerse sin autenticación ni cifrado.

### Configuración segura (en `/etc/docker/daemon.json`):

```json
{
  "hosts": ["unix:///var/run/docker.sock", "tcp://127.0.0.1:2376"],
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem"
}
```

---

## 4. Usar perfiles de AppArmor o SELinux

Estos sistemas de control de acceso ayudan a limitar las acciones de los contenedores en el sistema.

### Ejemplo con AppArmor:

```bash
docker run --security-opt apparmor=docker-default -it ubuntu
```

También podemos crear perfiles personalizados para mayor control.

---

## 5. Usar namespaces y usuarios no privilegiados

Docker puede mapear usuarios dentro del contenedor a usuarios no privilegiados en el host.

### Habilitar `userns-remap`:

Modificar `/etc/docker/daemon.json`:

```json
{
  "userns-remap": "default"
}
```

Esto hace que incluso si un contenedor corre como `root`, en el host ese usuario esté mapeado a un UID sin privilegios.

---

## 6. Escanear imágenes y minimizar su tamaño

Cuanto más pequeña sea una imagen, menos superficie de ataque tendrá. Además, debemos escanear las imágenes con herramientas como:

- `docker scan`
    
- [Trivy](https://github.com/aquasecurity/trivy)
    
- [Grype](https://github.com/anchore/grype)
    

### Ejemplo:

```bash
trivy image nginx
```

---

## 7. Definir políticas de red

Por defecto, todos los contenedores pueden hablar entre sí. Podemos aislar redes y controlar las conexiones.

### Crear red aislada:

```bash
docker network create --driver bridge --internal red_segura
```

### Usar esa red:

```bash
docker run --network red_segura -it ubuntu
```

---

## Cheatsheet: Hardening Docker

|Acción|Comando / Configuración|Propósito|
|---|---|---|
|Eliminar privilegios|`--cap-drop=ALL`|Mínimo privilegio|
|Proteger Docker API|TLS en `2376`|Autenticación segura|
|Evitar socket Docker|No montar `docker.sock`|Evitar RCE desde contenedor|
|Habilitar userns|`userns-remap` en `daemon.json`|Ejecutar como usuario no root|
|Usar AppArmor|`--security-opt apparmor=perfil`|Confinamiento de procesos|
|Escaneo de imágenes|`trivy`, `docker scan`|Buscar vulnerabilidades|
|Aislar redes|`--network red_privada`|Limitar comunicaciones|

---

## Conclusión

Al aplicar estas prácticas, podemos reducir drásticamente los riesgos asociados al uso de contenedores Docker. Si bien Docker es una herramienta poderosa, su seguridad depende de cómo lo utilicemos. Como profesionales en ciberseguridad, debemos entender tanto su poder como sus limitaciones.

> Recordemos siempre: **configurar de forma segura desde el inicio es más efectivo que mitigar ataques después**.

---
