
# Penelope Shell Handler — Tutorial práctico para Pentesting

Penelope es un shell handler pensado para acelerar tareas de post‑explotación (auto‑upgrade a PTY, múltiples sesiones, transferencia de archivos, ejecución de scripts en memoria, logging, etc.). En esta guía verás instalación, uso rápido y flujos típicos en pentesting. Para saber más acuda a la fuente oficial: [GitHub - Penelope](https://github.com/brightio/penelope)

---

## 1) Instalación y requisitos

- Requisitos: Python 3.6+; sistemas Unix‑like (Linux, macOS, BSD). En Windows, usa WSL para la mejor compatibilidad.
- Método rápido (sin instalación): descargar el script y ejecutarlo con Python 3.
- Método recomendado: instalar con pipx para usar el comando `penelope` en cualquier terminal.

Comandos de ejemplo (opcionales):

```bash
# Descargar y ejecutar directamente
wget https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py \
	&& python3 penelope.py

# Instalar con pipx (más limpio)
pipx install git+https://github.com/brightio/penelope
# Después podrás ejecutar: penelope
```


Solo falta **añadir la ruta de los binarios de pipx al PATH**, para que el comando `penelope` funcione desde cualquier terminal.

---

### Paso 1: Ejecutar el comando automático

```bash
pipx ensurepath
```

Este comando detecta tu shell (bash, zsh, fish, etc.) y añade automáticamente la ruta correspondiente —en tu caso `/home/metahumo/.local/bin`— al archivo de configuración (por ejemplo `~/.bashrc` o `~/.zshrc`).

---

### Paso 2: Actualizar la sesión actual

Después de ejecutar `pipx ensurepath`, cierra y vuelve a abrir la terminal, **o** ejecuta manualmente:

```bash
source ~/.bashrc
```

Esto recarga tu entorno y actualiza el PATH.

---

### Verificación

Comprueba que `penelope` está accesible:

```bash
which penelope
```

Si devuelve `/home/metahumo/.local/bin/penelope`, todo está correcto.

Y para confirmar la instalación:

```bash
penelope --version
```

---


## 2) Uso rápido (lo esencial)

- Escuchar reverse shells (por defecto 0.0.0.0:4444):

```bash
penelope
```

- Cambiar interfaz/puerto:

```bash
penelope -i eth0 -p 5555
```

- Mostrar payloads de reverse shell según listeners activos:

```bash
penelope -a
```

- Conectar a una bind shell en el objetivo:

```bash
penelope -c target -p 3333
```

- Obtener una reverse shell vía SSH (Penelope gestiona el listener):

```bash
penelope ssh user@target
penelope -p 5555 ssh user@target
```

- Servir ficheros/carpetas por HTTP (para transferencias rápidas):

```bash
penelope -s ./carpeta
```

Atajos de interacción:
- F12: volver al menú (si tienes PTY). Si no hay PTY, Ctrl‑D (readline) o Ctrl‑C (raw).
- El menú soporta autocompletado y abreviaturas (p. ej., `interact 1` → `i 1`).

## 3) Funciones clave (resumen)

- Auto‑upgrade a PTY con resize en tiempo real
- Logging de sesiones (con timestamps opcionales y colores)
- Descarga/subida de ficheros y carpetas (local/HTTP)
- Ejecución de scripts en memoria con descarga de salida en vivo
- Reenvío de puertos local (port forwarding)
- Múltiples sesiones/listeners y pestañas
- Mantener X shells activas por host (persistencia operativa)

Nota: algunas acciones como `spawn/script/portfwd` están soportadas actualmente en shells Unix. Soporte Windows en progreso.

## 4) Flujo típico de post‑explotación

1. Levanta un listener y muestra payloads (`-a`) para copiar el que encaje con el target.
2. Recibe la shell y deja que Penelope haga auto‑upgrade a PTY; usa F12 para entrar al menú.
3. Ejecuta linPEAS en memoria y guarda la salida en tu equipo (sin tocar disco del target).
4. Sube herramientas o descarga evidencia/créditos.
5. Abre una segunda shell con `spawn` para tareas largas.
6. Si hace falta, usa port forwarding para alcanzar servicios internos expuestos en loopback.
7. Con `-m NUM`, mantén N shells activas para no perder acceso si muere una sesión.

## 5) Chuleta de opciones (CLI)

Reverse/Bind:
- `-i, --interface` interfaz/IP de escucha (default 0.0.0.0)
- `-p, --port` puerto de escucha/conexión/servidor
- `-c, --connect` conectar a bind shell en HOST
- `-a, --payloads` mostrar payloads de reverse shell

Logging:
- `-L, --no-log` desactivar logs de sesión
- `-T, --no-timestamps` sin marcas de tiempo
- `-CT, --no-colored-timestamps` timestamps sin color

Servidor de ficheros:
- `-s, --serve` servir por HTTP
- `--url-prefix` prefijo de URL

Control de sesiones:
- `-m, --maintain NUM` mantener NUM shells activas por host
- `-M, --menu` ir directo al menú
- `-S, --single-session` aceptar sólo la primera sesión
- `-C, --no-attach` no auto‑adjuntar sesiones nuevas
- `-U, --no-upgrade` no intentar upgrade a PTY

Misc/Debug:
- `-l, --interfaces` listar interfaces disponibles
- `-v, --version` versión
- `-d, --debug` mensajes de depuración
- `-dd, --dev-mode` modo desarrollador
- `-cu, --check-urls` validar URLs internas

## 6) Comandos del menú (vista rápida)

- `interact <id>` / `i <id>`: adjuntar a sesión
- `sessions`: listar sesiones
- `download` / `upload`: transferencias (local/HTTP)
- `script`: ejecutar script en memoria
- `spawn`: nueva shell (otra pestaña)
- `portfwd`: reenvío de puertos (Unix)

## 7) Integraciones útiles

- Metasploit: desactiva el handler por defecto del exploit y deja a Penelope gestionar la shell:
	- `set DisablePayloadHandler True`
- Exploits en Python: puede importarse para recibir la shell en la misma terminal (ver `extras/` en el repo oficial).
- Enumeración: linPEAS y LSE funcionan muy bien junto a la ejecución en memoria y el logging de Penelope.

## 8) Solución de problemas

- Volver al menú sin matar la shell:
	- PTY: F12; Readline: Ctrl‑D; Raw: Ctrl‑C
- Logs “raros” al verlos con `cat` tras usar programas de pantalla completa (nano, reset):
	- Es un “Known Issue”; los datos están ahí, pero hay secuencias de escape que afectan la visualización.
- Windows:
	- Usa WSL. Algunas funciones avanzadas aún no están implementadas para shells nativas de Windows.

## 9) OPSEC y ética

- Usa Penelope únicamente con autorización explícita.
- El logging ayuda a auditoría, pero revisa qué información sensible queda registrada.
- Prefiere ejecución en memoria para reducir rastro en disco del objetivo cuando sea posible.

## 10) Referencias

- Repositorio oficial: https://github.com/brightio/penelope


---
