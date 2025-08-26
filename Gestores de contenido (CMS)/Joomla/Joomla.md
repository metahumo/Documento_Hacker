
---

# Definición

> Joomla es un CMS (Content Management System) de código abierto escrito en PHP, usado para crear y administrar sitios web dinámicos. Permite gestionar contenido sin necesidad de conocimientos avanzados de programación, ofreciendo extensibilidad mediante plantillas y módulos. Es popular por su flexibilidad y comunidad activa.

---

## Directorios vulnerables en Joomla

En una instalación por defecto de Joomla, existen varios directorios que pueden ser vulnerables si no se configuran adecuadamente. Estos directorios contienen archivos sensibles que, si no se gestionan correctamente, pueden ser objetivo de un atacante. A continuación te menciono los directorios más comunes en una instalación de Joomla y los riesgos asociados si no se configuran bien:

### 1. /administrator/
**Descripción**: Este es el directorio donde se encuentra el panel de administración de Joomla.  
**Riesgos**:  
- **Acceso no autorizado**: Si no se protege adecuadamente (por ejemplo, mediante autenticación adicional, firewall o IP restringida), un atacante podría obtener acceso al panel de administración.  
- **Ataques de fuerza bruta**: Sin limitaciones adecuadas en los intentos de login o una contraseña segura, este directorio puede ser blanco de ataques de fuerza bruta.  

### 2. /media/
**Descripción**: Contiene los archivos multimedia cargados a través del administrador de medios de Joomla.  
**Riesgos**:  
- **Subida de archivos maliciosos**: Si no se controla bien el tipo de archivos que se pueden subir (por ejemplo, permitiendo archivos .php o .exe), un atacante podría subir scripts maliciosos.  
- **Acceso a archivos sensibles**: Si no se establece una correcta configuración de permisos, un atacante podría acceder a archivos sensibles dentro de este directorio.  

### 3. /components/
**Descripción**: Contiene los componentes principales de Joomla que gestionan la funcionalidad del sitio.  
**Riesgos**:  
- **Explotación de componentes vulnerables**: Los componentes de Joomla pueden tener vulnerabilidades conocidas que los atacantes pueden explotar si no se actualizan o gestionan adecuadamente.  
- **Instalación de componentes maliciosos**: Si un componente es de una fuente no confiable o mal desarrollado, podría comprometer la seguridad del sistema.  

### 4. /configuration.php
**Descripción**: Este archivo contiene la configuración principal de Joomla, incluyendo información crítica como las credenciales de la base de datos.  
**Riesgos**:  
- **Acceso a información sensible**: Si un atacante obtiene acceso a este archivo, podría comprometer la base de datos y otros elementos críticos de la instalación de Joomla.  
- **Protección insuficiente**: Este archivo debe estar protegido adecuadamente, por ejemplo, mediante reglas de servidor (como en .htaccess) para evitar el acceso público.  

### 5. /plugins/
**Descripción**: Contiene los plugins que extienden la funcionalidad de Joomla.  
**Riesgos**:  
- **Plugins vulnerables**: Si los plugins no se actualizan o provienen de fuentes no confiables, pueden introducir vulnerabilidades en el sistema. Algunos plugins mal desarrollados pueden permitir la ejecución de código malicioso.  
- **Plugins maliciosos**: Los plugins de fuentes no confiables o comprometidas podrían ser utilizados por los atacantes para obtener acceso al sistema.  

### 6. /templates/
**Descripción**: Contiene los templates (plantillas) activos y no activos de Joomla.  
**Riesgos**:  
- **Plantillas inseguras**: Las plantillas mal escritas o desactualizadas pueden contener vulnerabilidades que podrían ser explotadas por un atacante.  
- **Acceso a archivos de configuración**: Un template mal diseñado podría exponer archivos de configuración que los atacantes podrían aprovechar.  

### 7. /logs/
**Descripción**: Directorio que puede contener archivos de registro del sistema y de aplicaciones.  
**Riesgos**:  
- **Exposición de información sensible**: Los registros pueden contener detalles sobre vulnerabilidades y configuraciones del sistema, lo que puede ser útil para un atacante si no se gestionan adecuadamente.  
- **Acceso no autorizado**: Los permisos de acceso deben ser estrictos para evitar que un atacante pueda leer los archivos de registro.  

### 8. /installation/
**Descripción**: Este directorio se utiliza durante el proceso de instalación de Joomla.  
**Riesgos**:  
- **Vulnerabilidad post-instalación**: Si este directorio no se elimina después de la instalación, podría ser explotado por los atacantes para obtener acceso al sistema.  

### 9. /administrator/index.php
**Descripción**: Archivo utilizado para el acceso al backend de Joomla, gestionando la interfaz administrativa.  
**Riesgos**:  
- **Vulnerabilidades de seguridad en el backend**: Si este archivo no se protege adecuadamente o el sitio no se mantiene actualizado, puede ser un blanco para ataques, como inyecciones SQL o XSS.  
- **Acceso no autorizado**: Es crucial implementar medidas de protección, como autenticación adicional o acceso restringido a ciertas IPs.  

---
