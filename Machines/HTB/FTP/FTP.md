# Explotación del Servicio FTP

## Introducción  

> El **File Transfer Protocol (FTP)** es un protocolo de transferencia de archivos entre sistemas. Si está mal configurado, puede permitir acceso anónimo o la subida de archivos maliciosos, lo que facilita la escalada de privilegios o acceso no autorizado.  

---

## 1. Escaneo inicial con `nmap`
```bash
nmap -p- --open -sV -n -Pn -sS -v --min-rate 5000 IP_objetivo
```
**Resultado esperado:**
```
PORT     STATE SERVICE
21/tcp   open  ftp
```
**Detectamos que el puerto 21 está abierto con el servicio FTP activo.**

---

![Captura](./imagenes/nmap_initial_scan.png)

## 2. Escaneo detallado con scripts de `nmap`
```bash
nmap -p 21 -sV -sC -n -Pn -sS -v --min-rate 5000 IP_objetivo
```
**Posible resultado:**
```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Feb 25  2021 pub
```
**Análisis del resultado:**  
-**Acceso anónimo permitido** → Podemos conectarnos sin credenciales.
-**Directorio `pub` disponible** → Puede contener archivos sensibles.

![Captura](./imagenes/nmap_servicios_ftp.png)
---

## 3. Acceso al FTP y enumeración de archivos  
### **3.1 Conexión al FTP anónimo**
```bash
ftp IP_objetivo
```
- **Usuario:** `anonymous`  
- **Contraseña:** [vacío o email falso]  

### **3.2 Listado de archivos**
```bash
ls
```
Si hay archivos interesantes, podemos descargarlos:
```bash
get nombre_del_archivo
```

---

## 4. Intento de subida de archivos  
Si la subida está permitida, podemos probar:
```bash
put archivo.txt
```
**Si funciona, podemos subir una web shell o un script para escalar privilegios.**

---

## 5. Búsqueda de vulnerabilidades en `vsftpd 3.0.3`  
### **5.1 Buscar exploits en `searchsploit`**
```bash
searchsploit vsftpd 3.0.3
```
### **5.2 Usar scripts de `nmap` para detección de vulnerabilidades**
```bash
nmap --script ftp-vuln* -p21 IP_objetivo
```

---

## 6. Explotación con `Metasploit`
```bash
msfconsole
search ftp  # o search vsftpd 3.0.3
use auxiliary/scanner/ftp/ftp_version
set RHOSTS IP_objetivo
run
```

---

## 7. Otras formas de detectar la versión del servicio FTP  
### **7.1 Con `netcat`**
```bash
nc -nv IP_objetivo 21
```
**Salida esperada:**
```
220 (vsFTPd 3.0.3)  # Versión del servicio
```

![Captura](./imagenes/nc_nv_ip_puerto.png)

### **7.2 Con `nmap --script=banner`**
```bash
nmap -sV --script=banner -p21 IP_objetivo
```
**Salida esperada:**
```
21/tcp open  ftp vsftpd 3.0.3
|_banner: 220 (vsFTPd 3.0.3)
```

![Captura](./imagenes/nmap_script_banner_fpt.png)

---

## Conclusión  
- Si **el acceso anónimo está habilitado**, podemos buscar archivos sensibles.  
- Si **podemos subir archivos**, podemos intentar una **web shell** o un **script de escalada de privilegios**.  
- Si el servicio es **vulnerable**, podemos explotarlo con **Metasploit o exploits públicos**.  



![Captura](./imagenes/secuencia_fpt.png)



