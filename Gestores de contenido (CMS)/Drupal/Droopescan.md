
---

# Definición

> **Droopescan** es una herramienta de seguridad diseñada para realizar auditorías en sitios web de Drupal, identificando vulnerabilidades conocidas en la plataforma como plugins desactualizados o mal configurados.

---
# Instalación

```bash
git clone https://github.com/SamJoan/droopescan
cd droopescan
python3 setup.py install
python3 -m venv vent_virtual
source vent_virtual/bin/activate
pip3 install -r requirements.txt
./droopescan
```

Repositorio oficial: https://github.com/SamJoan/droopescan

---
# Ejemplos de uso

```bash
droopescan scan drupal --url http://127.0.0.1:31337
```

```bash
droopescan scan -u http://127.0.0.1:31337
```

