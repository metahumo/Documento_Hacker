Script para **generar un JWT** 

```python
#!/usr/bin/env python3
"""
Genera un JWT con HS256 y clave 'secret'
Payload fijo: {"id": 2, "iat": 1749829182, "exp": 1749832782}
"""

import jwt  # PyJWT

header = {
    "alg": "HS256",
    "typ": "JWT"
}

payload = {
    "id": 2,
    "iat": 1749829182,
    "exp": 1749832782
}

secret = "secret"

token = jwt.encode(
    payload,
    secret,
    algorithm="HS256",
    headers=header
)

# PyJWT ≥ 2.0 devuelve str; en versiones < 2.0 devuelve bytes
if isinstance(token, bytes):
    token = token.decode()

print("JWT generado:")
print(token)

```