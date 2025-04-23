----
- Tags #web #wordpress #reconocimiento #herramientas #cms 
---
# Definición

> La herramienta **Wpscan**[^1] es comúnmente utilizada para enumerar páginas web que dispongan de un gestor de contenido [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/Gestores de contenido (CMS) 🌐/WordPress/WordPress|WordPress]]
---

# Instalación

```bash
git clone https://github.com/wpscanteam/wpscan.git
cd wpscan
bundle install
wpscan --version
```

Repositorio oficial: https://github.com/wpscanteam/wpscan
# Ejemplos de uso

```bash
wpscan --url http://127.0.0.1:31337

wpscan -url http://127.0.0.1:31337 -e vp,u
```

-e --> identificar plugin (vp) y usuarios (u)

Usar API TOKEN para mejorar el escaneo, registrarse en esta página: https://wpscan.com/api/

API Token--> zzqD4pgsrFUtRKsOgc5voC70bgbJyZEsz8sb1Fi54YU

```bash
wpscan --url http://127.0.0.1:31337 -e vp --api-token="zzqD4pgsrFUtRKsOgc5voC70bgbJyZEsz8sb1Fi54YU"
```

Forzar contraseña con wpscan:

```bash 
wpscan --utl http://127.0.0.1:31337 -U USUARIO_DETECTADO -P /usr/share/wordlists/rockyou.txt
```

Podemos aplicar ejercicios de fuerza bruta sobre el archivo **xmlrpc.php**. Para ello sería necesario crear un [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/Gestores de contenido (CMS) 🌐/WordPress/Script]] de *Bash* o *Python* que nos permita hacer este procedimiento de forma manual [^2].

--- 
## Referencias

[^1]: Página oficial de la herramienta: [GitHub-Wpsan](https://github.com/wpscanteam/wpscan)
[^2]: Procedimiento manual para la explotación del XML-RPC: [[Documento Hacker/Gestores de contenido (CMS) 🌐/WordPress/XMLRPC]]
