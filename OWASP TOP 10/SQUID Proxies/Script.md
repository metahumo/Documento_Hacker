
---

Script para **descubrir puertos** a través del proxy

```python
#!/usr/env/bin python3

import sys, signal, requests

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

main_url = "http://127.0.0.1"
squid_proxy = {'http': 'http://192.168.1.62:3128'}

def portDiscovery():

    common_tcp_ports = {20,21,22,23,25,53,67,68,69,80,110,111,135,137,138,139,143,161,162,179,389,443,445,465,512,513,514,587,631,993,995,1080,1433,1434,1521,1723,2049,2082,2083,2483,2484,3306,3389,3690,4444,5432,5900,5985,5986,8080}

    for tcp_port in common_tcp_ports:

        r = requests.get(main_url + ':' + str(tcp_port), proxies=squid_proxy)

        if r.status_code != 503:
            print("\n[+] Port " + str(tcp_port) + " - OPEN")

if __name__ == '__main__':

    portDiscovery()
```

Ejemplo de resultado:

```bash
[+] Port 22 - OPEN

[+] Port 80 - OPEN

[+] Port 3306 - OPEN
```