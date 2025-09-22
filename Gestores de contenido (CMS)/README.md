
---

# CMS (Gestores de Contenido)

Este directorio contiene scripts, herramientas y técnicas orientadas al análisis, explotación y pruebas de seguridad sobre gestores de contenido (CMS) como WordPress, Joomla, Drupal y otros sistemas web populares.

## Contenido

- **WordPress**: Scripts de análisis de vulnerabilidades, brute force de usuarios y plugins inseguros.
- **Joomla/Drupal**: Ejemplos de explotación y pruebas de seguridad en estas plataformas.
- **Automatización**: Scripts en Python y Bash para facilitar la auditoría y la recopilación de información sobre CMS.
- **Explotación web**: Fuzzers, payloads y pruebas de endpoints específicos de CMS.
- **Ejemplos y pruebas**: Archivos de salida de tests y configuraciones de laboratorio para demostrar el funcionamiento de los scripts.

---

## Instalación

- Clona el repositorio:

```bash
git clone https://github.com/metahumo/Documento_Hacker.git
cd Documento_Hacker/Gstores de contenido (CMS)/
````

* Instalar dependencias de Python:

```bash
pip install -r requirements.txt
```

* Alternativamente, instalar bibliotecas individuales según necesidad:

```bash
pip install requests beautifulsoup4 paramiko
```

* Scripts Bash: No requieren instalación, solo permisos de ejecución:

```bash
chmod +x nombre_script.sh
./nombre_script.sh
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

3. Consultar los ejemplos de prueba para entender cómo aplicar cada herramienta en entornos de laboratorio.

> Nota: Todos los scripts están diseñados para entornos controlados o pruebas autorizadas. No se deben ejecutar en sistemas de terceros sin consentimiento.

---

## Recomendaciones

* Mantener actualizado el archivo `requirements.txt` al añadir nuevas dependencias.
* Revisar los scripts antes de ejecutarlos para evitar conflictos o problemas de permisos.
* Documentar cualquier cambio o personalización de scripts para mantener consistencia y trazabilidad en el repositorio.

```

---
