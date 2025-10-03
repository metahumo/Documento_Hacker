
---

# Inyecciones SQL

Este directorio contiene scripts, tutoriale y resolución de ejercios de Portswigger.

Para obtener información y tutoriales sobre bases de datos visitar: [Bases de datos SQL](../Bases%20de%20datos/SQL/)

## Contenido

- **Python**: Scripts de automatización, SQLi, herramientas de explotación y pruebas de seguridad. Incluye el uso de bibliotecas como `requests` y `pwn` .
- **Ejemplos y pruebas**: Archivos de ejemplo y salidas de prueba para mostrar el funcionamiento de diferentes tipos de inyecciones SQL.

---

## Recomendación para la correcta instalación y uso de librerías

---

### Dependencias pwn

#### crear y activar venv

```bash
python3 -m venv ~/venvs/pwntools-venv
source ~/venvs/pwntools-venv/bin/activate
```

#### actualizar pip y setuptools

```bash
python -m pip install --upgrade pip setuptools
```

#### instalar pwntools

```bash
pip install pwntools
```

---

### Dependencias requests

#### crear y activar venv

```bash
python3 -m venv ~/venvs/requests-venv
source ~/venvs/requests-venv/bin/activate
```

#### actualizar pip y setuptools

```bash
python -m pip install --upgrade pip setuptools
```

#### instalar requests

```bash
pip install requests
```

#### comprobación rápida

```bash
python -c "import requests; print('requests OK, versión:', requests.__version__)"
```

--

## Requisitos / Instalación

Este script usa Python 3.

Clona el repositorio (o descarga los scripts asociados --> [Scripts](./Scripts/)): 
```bash
git clone https://github.com/metahumo/Documento_Hacker.git
cd Documento_Hacker/OWASP TOP 10/SQLi/
```

## con curl

```bash
curl -L -o SQLi.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/OWASP%20TOP%2010/SQLi/"
```

## con wget

```bash
wget -O SQLi.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/OWASP%20TOP%2010/SQLi/"
```

---

> Nota: Todos los scripts están diseñados para entornos controlados o pruebas autorizadas. No se deben ejecutar en sistemas de terceros sin consentimiento.

---

## Recomendaciones

* Revisar los scripts antes de ejecutarlos para evitar conflictos o problemas de permisos.

---
