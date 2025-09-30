
---

# PoC: Instalación y uso básico de quiche

## Introducción

>[quiche](https://github.com/cloudflare/quiche) es una implementación en Rust de **QUIC** y **HTTP/3** desarrollada por Cloudflare.  Permite trabajar con servidores y clientes que soporten este protocolo de transporte moderno, con foco en baja latencia y seguridad.

Este PoC muestra cómo clonar, compilar y ejecutar ejemplos básicos del repositorio.

---
## Requisitos previos

Acción: instalar `rustup`

```bash
curl https://sh.rustup.rs -sSf | sh

```

Acción: instalar `cargo`

```bash
source "$HOME/.cargo/env"
rustup update
```
## Instalación

Secuencia de acciones:

```bash
 git clone --recursive https://github.com/cloudflare/quiche
 cd quiche/
 cargo build --examples
 cargo test
```

---

## Ejemplo rápido de uso

### Servidor HTTP/3

Ejecuta el servidor de ejemplo (requiere certificados TLS válidos o autogenerados): podemos encontrar la ruta con `find \-name http3-client`

```bash
./target/debug/examples/http3-server --cert cert.crt --key cert.key 127.0.0.1 4433
```

### Cliente HTTP/3

En otra terminal, ejecuta el cliente contra el servidor:

```bash
./target/debug/examples/http3-client https://127.0.0.1:4433/
```

---

## Referencias

- [Repositorio oficial de quiche](https://github.com/cloudflare/quiche)
    
- [QUIC Working Group (IETF)](https://quicwg.org/)
    
- [Documentación de Cargo](https://doc.rust-lang.org/cargo/)
    

---
