
---

# Definición

> **MageScan** es una herramienta de escaneo de seguridad para Magento que permite identificar vulnerabilidades y configuraciones inseguras en instalaciones de Magento, ayudando a detectar posibles puntos de explotación.


---
# Instalación

```bash
git clone https://github.com/steverobbins/magescan magescan
cd magescan
```

Descargar archivo necesario para instalar `magescan`: https://github.com/steverobbins/magescan/releases

```bash
mv /home/TU_USUARIO/Descargas/magescan.phar .
php magescan.phar
```

Repositorio oficial: https://github.com/steverobbins/magescan

---
# Ejemplos de uso

## Opciones
  -h, --help            Muestra este mensaje de ayuda
  -q, --quiet           No mostrar ningún mensaje
  -V, --version         Muestra la versión de la aplicación
      --ansi            Fuerza la salida en formato ANSI
      --no-ansi         Deshabilita la salida en formato ANSI
  -n, --no-interaction  No realizar preguntas interactivas
  -v|vv|vvv, --verbose  Aumenta la verbosidad de los mensajes: 1 para salida normal, 2 para salida más detallada y 3 para depuración

## Comandos disponibles:
  help              Muestra la ayuda para un comando
  list                Muestra los comandos disponibles
  scan
    scan:all                Ejecuta todos los escaneos
    scan:catalog        Obtiene información del catálogo
    scan:modules      Obtiene los módulos instalados
    scan:patch           Obtiene información de los parches
    scan:server           Verifica la tecnología del servidor
	scan:sitemap        Verifica el mapa del sitio
    scan:unreachable Verifica rutas inalcanzables
    scan:version          Obtiene la versión de una instalación de Magento

```bash
php magescan.phar scan:all http://127.0.0.1:31337
```

---
