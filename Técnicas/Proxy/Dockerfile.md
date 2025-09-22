
---
```ini
FROM alpine:latest

RUN apk add --no-cache openssh sudo bash
RUN mkdir -p /var/run/sshd /var/log
RUN ssh-keygen -A
RUN adduser -D -u 1000 proxy_02 \
 && echo "proxy_02:1234" | chpasswd \
 && echo "proxy_02 ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true \
 && sed -i 's/AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config || echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config \
 && sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-E", "/var/log/sshd.log"]
```