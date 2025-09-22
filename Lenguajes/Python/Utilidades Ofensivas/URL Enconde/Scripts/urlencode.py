#!/usr/bin/env python3

import urllib.parse as url

def urlencode_payload():
    payload = input(f"\n[+] Introduzca el payload: ")
    encoded_once = url.quote(payload)
    encoded_twice = url.quote(encoded_once)

    print(f"\n[!] Payload URL-encoded: {encoded_once}\n")
    print(f"\n[!] Payload URL-encoded (2x): {encoded_twice}\n")

if __name__ == "__main__":
    urlencode_payload()
