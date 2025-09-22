
---
```yaml
services:
  socks1:
    image: socks-ssh:latest
    container_name: socks1
    networks:
      proxy_net:
        ipv4_address: 172.18.0.10
    ports:
      - "2222:22"
    restart: unless-stopped

  socks2:
    image: socks-ssh:latest
    container_name: socks2
    networks:
      proxy_net:
        ipv4_address: 172.18.0.11
    ports:
      - "2223:22"
    restart: unless-stopped

networks:
  proxy_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.18.0.0/16
```