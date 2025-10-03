# Recomendación para la correcta instalación y uso de librerías


---

## Dependencias pwn

### crear y activar venv

```bash
python3 -m venv ~/venvs/pwntools-venv
source ~/venvs/pwntools-venv/bin/activate
```

### actualizar pip y setuptools

```bash
python -m pip install --upgrade pip setuptools
```
### instalar pwntools

```bash
pip install pwntools
```

---

# Dependencias requests

### crear y activar venv

```bash
python3 -m venv ~/venvs/requests-venv
source ~/venvs/requests-venv/bin/activate
```

### actualizar pip y setuptools

```bash
python -m pip install --upgrade pip setuptools
```
### instalar requests

```bash
pip install requests
```
### comprobación rápida

```bash
python -c "import requests; print('requests OK, versión:', requests.__version__)"
```

---

# Requisitos / Instalación

Este script usa Python 3.

Clona el repositorio (o descarga el archivo SQLi_<tipo>.py ):

```bash
git clone https://github.com/metahumo/Documento_Hacker.git
cd Documento_Hacker/OWASP TOP 10/SQLi/Scripts/
python3 SQLi_blind_response.py --help
```

# con curl

```bash
curl -L -o fuzzer.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/OWASP%20TOP%2010/SQLi/Scripts/SQLi_blind_error.py"
```

# con wget

```bash
wget -O fuzzer.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/OWASP%20TOP%2010/SQLi/Scripts/SQLi_blind_response.py"
```

---
