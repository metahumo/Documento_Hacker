
---
# Cómo obtener una **contraseña de aplicación** de Google (Gmail) — pasos (2025)

> Resumen rápido: para generar una _contraseña de aplicación_ (16 caracteres) necesitas una cuenta Google (Gmail), **activar la verificación en dos pasos (2-Step Verification)** y desde la sección **App passwords** crear una nueva contraseña para la “app” que indiques (puedes usar _Other_ / _Custom name_ y poner un nombre descriptivo). La contraseña generada (16 caracteres) puede usarse en apps/dispositivos que no soportan el flujo moderno de OAuth para iniciar sesión y enviar correos (por ejemplo scripts que usan `smtplib`). ([Soporte de Google](https://support.google.com/accounts/answer/185833?hl=en&utm_source=chatgpt.com "Sign in with app passwords - Google Account Help"))

---

## Requisitos previos importantes

- La cuenta debe tener **2-Step Verification** activada. No se puede generar App Passwords sin 2SV. ([Soporte de Google](https://support.google.com/accounts/answer/185833?hl=en&utm_source=chatgpt.com "Sign in with app passwords - Google Account Help"))
    
- Algunas cuentas **no permiten App Passwords**: cuentas gestionadas por empresas/escuelas (Google Workspace) cuyo administrador lo haya bloqueado, cuentas con **Advanced Protection**, o cuentas configuradas para usar solo llaves de seguridad. Si no ves la opción, revisa estas restricciones. ([Soporte de Google](https://support.google.com/accounts/answer/185833?hl=en&utm_source=chatgpt.com "Sign in with app passwords - Google Account Help"))
    

---

## Pasos (secuencia) para obtener la contraseña de aplicación

1. Abre tu cuenta Google y ve a la configuración de seguridad:  
    `https://myaccount.google.com/security` y accede con tu cuenta Gmail. ([myaccount.google.com](https://myaccount.google.com/apppasswords?utm_source=chatgpt.com "App passwords - Sign in - Google Accounts"))
    
2. Activa la **Verificación en dos pasos (2-Step Verification)** si no la tienes ya:
    
    - En _Security_ → _How you sign in to Google_ → _2-Step Verification_ → _Get started_.
        
    - Sigue los pasos en pantalla (teléfono, app de autenticación o método soportado). ([Soporte de Google](https://support.google.com/accounts/answer/185839?co=GENIE.Platform%3DAndroid&hl=en&utm_source=chatgpt.com "Turn on 2-Step Verification - Android - Google Account Help"))
        
3. Tras activar 2SV regresa a la sección **Security** y busca **App passwords** (o ve directamente a `https://myaccount.google.com/apppasswords`):
    
    - Si te lo solicita, vuelve a iniciar sesión para verificar tu identidad. ([myaccount.google.com](https://myaccount.google.com/apppasswords?utm_source=chatgpt.com "App passwords - Sign in - Google Accounts"))
        
4. En **App passwords**:
    
    - En _Select app_ elige una opción o selecciona **Other (Custom name)**.
        
    - Introduce un nombre descriptivo (por ejemplo: `Keylogger_PoC` o `SMTP_script_server`) y pulsa **Create / Generate**. ([itsupport.umd.edu](https://itsupport.umd.edu/itsupport/?id=kb_article_view&sysparm_article=KB0015112&utm_source=chatgpt.com "Create an App Password for Gmail - IT Support - IT Service Desk"))
        
5. Google generará una **contraseña de 16 caracteres** (sin espacios) que verás en pantalla. **Cópiala** en un lugar seguro — la verás solo en ese momento. Esa es la contraseña que debes usar en lugar de tu contraseña normal para apps que no soportan OAuth. ([Soporte de Google](https://support.google.com/accounts/answer/185833?hl=en&utm_source=chatgpt.com "Sign in with app passwords - Google Account Help"))
    
6. Opcional: cuando cambies tu contraseña principal de Google se revocan las app passwords; revócalas manualmente desde la misma página si dejas de usar una app o dispositivo. ([Soporte de Google](https://support.google.com/accounts/answer/185833?hl=en&utm_source=chatgpt.com "Sign in with app passwords - Google Account Help"))
    

---

## Ejemplo de uso (enviar correo desde un script Python)

_(no pongas credenciales reales en el código: usa variables o un gestor de secretos)_

```python
import smtplib
from email.mime.text import MIMEText

smtp_host = "smtp.gmail.com"
smtp_port = 465
sender = "tu_email@gmail.com"
app_password = "xxxxxxxxxxxxxxxx"  # la contraseña de 16 caracteres generada por Google

msg = MIMEText("Cuerpo del mensaje")
msg["Subject"] = "Prueba"
msg["From"] = sender
msg["To"] = "destino@example.com"

with smtplib.SMTP_SSL(smtp_host, smtp_port) as s:
    s.login(sender, app_password)
    s.sendmail(sender, ["destino@example.com"], msg.as_string())
```

> Nota: Google recomienda usar contraseñas de aplicación **solo** si la app no soporta Sign in with Google / OAuth. Para integraciones más complejas, evalúa usar OAuth2 con las bibliotecas oficiales. ([help.meetalfred.com](https://help.meetalfred.com/en/articles/8160682-set-up-smtp-for-gmail-app-password-guide?utm_source=chatgpt.com "Set up SMTP for Gmail (App Password Guide)"))

---

## Posibles problemas y mensajes frecuentes

- **No veo “App passwords”**: puede ser porque tienes activado sólo el método de llaves de seguridad para 2SV, usas una cuenta de organización (Workspace) con la opción desactivada, o la cuenta está en Advanced Protection. Revisa la página de ayuda de Google para detalles. ([Soporte de Google](https://support.google.com/accounts/answer/185833?hl=en&utm_source=chatgpt.com "Sign in with app passwords - Google Account Help"))
    
- **Funciona una vez y deja de funcionar**: al cambiar la contraseña de la cuenta principal, Google revoca automáticamente las app passwords. Genera una nueva si es necesario. ([Soporte de Google](https://support.google.com/accounts/answer/185833?hl=en&utm_source=chatgpt.com "Sign in with app passwords - Google Account Help"))
    

---

## Referencias oficiales y lectura adicional

- Google Support — _Sign in with app passwords_ (crear y gestionar App Passwords). ([Soporte de Google](https://support.google.com/accounts/answer/185833?hl=en&utm_source=chatgpt.com "Sign in with app passwords - Google Account Help"))
    
- Google Support — _Turn on 2-Step Verification_. ([Soporte de Google](https://support.google.com/accounts/answer/185839?co=GENIE.Platform%3DAndroid&hl=en&utm_source=chatgpt.com "Turn on 2-Step Verification - Android - Google Account Help"))
    
- Página directa de App Passwords (inicia sesión): `https://myaccount.google.com/apppasswords`. ([myaccount.google.com](https://myaccount.google.com/apppasswords?utm_source=chatgpt.com "App passwords - Sign in - Google Accounts"))
    
- Guías técnicas / SMTP y App Passwords (ej.: configurar SMTP para gmail con App Password). ([help.meetalfred.com](https://help.meetalfred.com/en/articles/8160682-set-up-smtp-for-gmail-app-password-guide?utm_source=chatgpt.com "Set up SMTP for Gmail (App Password Guide)"))
    

---

## Aviso de seguridad y buenas prácticas

- **No metas la app password en código fuente público ni en repositorios.** Usa gestores de secretos o variables de entorno.
    
- Si el servicio exige enviar correos desde scripts/servidores, prefiere mecanismos más seguros (OAuth2, cuentas servicio, o APIs oficiales) cuando sea posible.
    
- Revoca app passwords que ya no uses y habilita registros/alerts para actividad sospechosa en tu cuenta. ([Soporte de Google](https://support.google.com/accounts/answer/185833?hl=en&utm_source=chatgpt.com "Sign in with app passwords - Google Account Help"))
    

---
