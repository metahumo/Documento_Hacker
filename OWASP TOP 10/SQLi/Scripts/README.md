# Recomendación para la correcta instalación y uso de librerías

**Dependencias pwn**

## crear y activar venv
python3 -m venv ~/venvs/pwntools-venv
source ~/venvs/pwntools-venv/bin/activate

## actualizar pip y setuptools
python -m pip install --upgrade pip setuptools

## instalar pwntools
pip install pwntools

**Dependencias requests**

## crear y activar venv
python3 -m venv ~/venvs/requests-venv
source ~/venvs/requests-venv/bin/activate

## actualizar pip y setuptools
python -m pip install --upgrade pip setuptools

## instalar requests
pip install requests

## comprobación rápida
python -c "import requests; print('requests OK, versión:', requests.__version__)"
