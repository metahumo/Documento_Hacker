
---
- Tags: #web #configuración 
---
# Iniciar y Detener  Servicios de Apache2 y MariaDB

## Iniciar los Servicios

Si necesitas retomar el ejercicio en otro momento, puedes reiniciar los servicios de Apache2 y MariaDB con los siguientes comandos:

1. **Iniciar Apache2**:
    
```bash
sudo systemctl start apache2
```
    
2. **Iniciar MariaDB**:
    
```bash
sudo systemctl start mariadb
```
    

Una vez iniciados, puedes verificar su estado con los mismos comandos `status`, o acceder al servidor web local.

## Detener los Servicios

Es recomendable detener los servicios de Apache2 y MariaDB cuando no los estés utilizando, para liberar recursos y evitar que sigan ejecutándose innecesariamente. Para detener los servicios, usa los siguientes comandos:

1. **Detener Apache2**:
```bash
sudo systemctl stop apache2
```

2. **Detener MariaDB**:
    
```bash
sudo systemctl stop mariadb
```
    

Para verificar que los servicios se han detenido correctamente, usa los siguientes comandos:

- Para Apache2:
    
```bash
sudo systemctl status apache2
```
    
- Para MariaDB:
    
```bash
sudo systemctl status mariadb
```
    

Ambos deberían mostrar que los servicios no están activos.

---
## Habilitar los Servicios al Inicio (Opcional)

Si deseas que los servicios de Apache2 y MariaDB se inicien automáticamente cada vez que reinicias tu sistema, puedes habilitarlos con los siguientes comandos:

```bash
sudo systemctl enable apache2
sudo systemctl enable mariadb
```

Esto hará que los servicios se inicien automáticamente en el próximo arranque del sistema.

---

## Resumen


- **Inicia** los servicios cuando quieras continuar trabajando en el ejercicio.

- **Detén** los servicios de Apache2 y MariaDB cuando no los necesites.
    
- Si se prefiere, **habilita** los servicios para que se inicien automáticamente al reiniciar el sistema.
    
