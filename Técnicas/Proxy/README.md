
---

# Proxy

Este directorio contiene técnicas, scripts y configuraciones relacionadas con el uso de proxies para pruebas de seguridad ofensiva y pentesting.

## Contenido

- **Docker**: Contenedores configurados para levantar proxies SOCKS y HTTP de manera rápida y reproducible.
- **Scripts de inicio**: Scripts `start_docker.sh` y similares para automatizar la creación, ejecución y limpieza de contenedores proxy.
- **Configuraciones SSH**: Archivos `Dockerfile` y configuraciones de `sshd` para permitir conexiones seguras a los contenedores proxy.
- **Cadenas de proxies**: Ejemplos de encadenamiento de proxies para anonimato o pruebas de evasión de filtros.
- **Notas y pruebas**: Archivos de ejemplo y salidas de pruebas que muestran cómo utilizar los proxies en entornos controlados.

---

## Instalación

- Clona el repositorio (o descarga los archivo `.sh`):

```bash
git clone https://github.com/metahumo/Documento_Hacker.git
cd Documento_Hacker/Técnicas/Proxy/
```

- Con curl

  ```bash
  curl -L -o fuzzer.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/Lenguajes/Python/Utilidades%20Ofensivas/Fuzzer/Script/fuzzer.py"
  ```

- Con wget

  ```bash
  wget -O fuzzer.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/Lenguajes/Python/Utilidades%20Ofensivas/Fuzzer/Script/fuzzer.py"
  ```

---

## Uso

1. Construir los contenedores:

    ```bash
   sudo docker build -t socks-container .
    ```

2. Levantar los proxies con el script de inicio:

   ```bash
   ./start_docker.sh
   ```
   
3. Configurar clientes para usar los proxies generados (SOCKS5/HTTP) según la documentación interna de cada script.
   
5. Limpiar contenedores y redes:

   ```bash
   ./stop_docker.sh
   ```

> Nota: Todos los scripts y configuraciones están diseñados para entornos de laboratorio o pruebas autorizadas. No se deben usar en sistemas de terceros sin consentimiento.

---

## Recomendaciones

* Revisar y adaptar las configuraciones de SSH y contraseñas antes de usar en entornos reales.
* Mantener un control de las IPs y puertos para evitar conflictos en el sistema host.
* Actualizar cualquier cambio en scripts o Dockerfiles para mantener consistencia con ajustes especificos de cada sistema y entorno.

```

---
