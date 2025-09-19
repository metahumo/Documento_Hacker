
---

# Enumeración de usuarios SSH (CVE-2018-15473)

En este repositorio encontraremos un script para **enumerar usuarios válidos en servidores SSH**.
La vulnerabilidad explotada corresponde a **CVE-2018-15473**, presente en versiones de OpenSSH anteriores a **7.7**, que permiten diferenciar respuestas del servidor según si el usuario existe o no durante la autenticación. Esto nos permite identificar usuarios válidos de manera remota.

---

## Requisitos / Instalación

Este script usa **Python 3** y la librería **Paramiko**.

Podemos obtener el script desde el repositorio:

```bash
git clone https://github.com/metahumo/Documento_Hacker.git
cd Documento_Hacker/Lenguajes/Python/Utilidades\ Ofensivas/Enumeración\ ssh/Script/
python3 ssh_enum.py --help
```

También podemos descargar el archivo directamente:

**Con curl:**

```bash
curl -L -o ssh_enum.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/Lenguajes/Python/Utilidades%20Ofensivas/Enumeración%20ssh/Script/ssh_enum.py"
```

**Con wget:**

```bash
wget -O ssh_enum.py "https://raw.githubusercontent.com/metahumo/Documento_Hacker/main/Lenguajes/Python/Utilidades%20Ofensivas/Enumeración%20ssh/Script/ssh_enum.py"
```

Instalamos dependencias:

```bash
python3 -m pip install --user paramiko
```

> En entornos virtuales: crea y activa un `venv` y luego `pip install paramiko`.

---

## Uso básico

```bash
python3 ssh_enum.py <target> -p <port> <username>
```

Ejemplo:

```bash
python3 ssh_enum.py 192.168.1.74 -p 22 root
```

* Si el usuario existe → `[+] root es un usuario válido`
* Si el usuario no existe → `[-] root no es un usuario válido`

---

## Tabla de parámetros (resumen)

| Parámetro  | Descripción                                   | Ejemplo      |
| ---------- | --------------------------------------------- | ------------ |
| target     | Dirección IP o hostname del objetivo (oblig.) | 192.168.110.74 |
| -p, --port | Puerto SSH del servidor                       | -p 22        |
| username   | Usuario a validar                             | root         |

---

## Qué hace el script

Breve resumen:

* Conecta a un servidor SSH usando Paramiko.
* Envía un paquete especial que explota la diferencia de respuesta en autenticación.
* Determina si el usuario existe sin necesidad de contraseña.
* Permite identificar cuentas válidas de manera rápida para pruebas de pentesting.

---

## Buenas prácticas y advertencias

* Solo prueben objetivos para los que tengan **permiso explícito**. Ejecutar scans en sistemas sin autorización puede ser ilegal.
* Este script es para **propósitos educativos y pruebas controladas**.
* Revisen los resultados y logs con cuidado para análisis posterior.

---

## Licencia y atribución

Este repositorio contiene material de aprendizaje y pruebas.
Úsalo bajo tu propia responsabilidad y respeta las leyes y políticas de uso de los sistemas objetivo.
El exploit original fue desarrollado por **Matthew Daley, Justin Gardner y Lee David Painter**, y nuestra versión está adaptada a Python 3 para compatibilidad actual.

---
