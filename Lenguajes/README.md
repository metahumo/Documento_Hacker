
---

# Lenguajes

Este directorio contiene scripts, bibliotecas y utilidades ofensivas desarrolladas en distintos lenguajes de programación, principalmente Python, Bash y PHP, para pruebas de seguridad y pentesting.

## Contenido

- **Python**: Scripts de automatización, fuzzers, herramientas de explotación y pruebas de seguridad. Incluye el uso de bibliotecas como `requests`, `cryptography.fernet`, `paramiko` y `scapy`.
- **Bash/Shell**: Scripts para automatizar tareas en sistemas Linux, manipulación de redes, proxies y ejecución de comandos remotos.
- **PHP**: Scripts y ejemplos para pruebas de seguridad web, explotación de vulnerabilidades y pruebas de endpoints.
- **Ejemplos y pruebas**: Archivos de ejemplo y salidas de prueba para mostrar el funcionamiento de cada script en entornos controlados.

---

## Instalación

- Clona el repositorio:

```bash
git clone https://github.com/metahumo/Documento_Hacker.git
cd Documento_Hacker/Lenguajes/
````

* Instalar dependencias de Python:

```bash
pip install -r requirements.txt
```

* Alternativamente, instalar bibliotecas individuales según necesidad:

```bash
pip install requests cryptography paramiko scapy
```

* Scripts Bash y PHP: No requieren instalación adicional, solo dar permisos de ejecución si es necesario:

```bash
chmod +x nombre_script.sh
./nombre_script.sh

php nombre_script.php
```

---

## Uso

1. Ejecutar scripts Python:

```bash
python3 script.py
```

2. Ejecutar scripts Bash:

```bash
./script.sh
```

3. Ejecutar scripts PHP:

```bash
php script.php
```

4. Consultar los ejemplos de prueba para entender cómo aplicar cada herramienta en entornos de laboratorio.

> Nota: Todos los scripts están diseñados para entornos controlados o pruebas autorizadas. No se deben ejecutar en sistemas de terceros sin consentimiento.

---

## Recomendaciones

* Mantener actualizado el archivo `requirements.txt` al añadir nuevas dependencias.
* Revisar los scripts antes de ejecutarlos para evitar conflictos o problemas de permisos.
* Documentar cualquier cambio o personalización de scripts para mantener consistencia y trazabilidad en el repositorio.

---
