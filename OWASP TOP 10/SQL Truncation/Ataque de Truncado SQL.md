# Ataque de Truncado SQL (SQL Truncation)

En esta sección vamos a estudiar en profundidad el **ataque de truncado SQL**, una técnica que explota cómo algunos sistemas gestionan longitudes de campos en bases de datos. Este ataque puede permitir a un atacante eludir controles de unicidad o integridad en campos como el correo electrónico o el nombre de usuario, y en casos más graves, hacerse pasar por otro usuario legítimo, como un administrador.

## ¿Qué es el truncado SQL?

El truncado SQL se produce cuando una cadena de entrada supera la longitud máxima definida para un campo en la base de datos, y esta es recortada (truncada) automáticamente antes de su almacenamiento. Si no se validan correctamente tanto el contenido como la longitud del dato antes de insertarlo, esto puede ser explotado por un atacante.

## Ejemplo práctico

Supongamos que desarrollamos una aplicación web que permite a los usuarios registrarse con su correo electrónico y una contraseña. En la base de datos, el campo para almacenar los correos electrónicos tiene una longitud máxima de **17 caracteres** (`VARCHAR(17)`).

Ahora imaginemos que el usuario `admin@admin.com` ya existe en la base de datos. Este correo tiene 15 caracteres, por lo tanto, si alguien intenta registrarse con ese mismo correo, la base de datos detectará una entrada duplicada y rechazará la operación.

Sin embargo, un atacante astuto podría intentar registrarse con la dirección `admin@admin.com  a` (dos espacios y una "a"). Esta cadena tiene 18 caracteres en total, por lo que excede el límite de la base de datos.

Cuando intentamos insertar ese valor en un campo `VARCHAR(17)`, el sistema recorta la cadena a los primeros 17 caracteres: `admin@admin.com  ` (termina en dos espacios). Si la base de datos elimina automáticamente los espacios al final (algo común en algunas configuraciones), el valor final insertado será `admin@admin.com`, el mismo que el usuario original.

Como resultado, el sistema puede aceptar el nuevo registro y **actualizar la entrada existente** con una nueva contraseña, sin mostrar errores. Esto ocurre porque no se validó ni la longitud ni el contenido del campo antes de insertarlo.

Con este truco, acabamos **tomando el control de la cuenta de otro usuario** simplemente manipulando la longitud de entrada.

## Máquina *Tornado* de VulnHub

Este tipo de vulnerabilidad puede encontrarse en entornos reales mal configurados. Un buen ejemplo lo encontramos en la máquina [[Tornado]] de VulnHub, diseñada para entrenar habilidades ofensivas en ciberseguridad.

En esta máquina, se nos plantea un entorno vulnerable donde podemos explotar exactamente este tipo de truncado de datos. Durante el ejercicio, utilizamos un campo de registro para usuarios, manipulamos la longitud del correo electrónico y, mediante truncado, conseguimos sobrescribir la contraseña de un usuario legítimo sin alertar al sistema.

Podemos descargar y probar esta máquina desde el siguiente enlace:

[Máquina Tornado de Vulnhub](https://www.vulnhub.com/entry/ia-tornado,639/)

Es un laboratorio perfecto para entender en la práctica los riesgos reales que conlleva ignorar la validación estricta de datos.

## Cómo prevenir este ataque

Para evitar este tipo de vulnerabilidades, debemos aplicar una serie de buenas prácticas:

- **Validar la longitud de entrada en el backend**, no confiar nunca en el límite del frontend.
- **Eliminar espacios al principio y al final** de las cadenas antes de insertarlas en la base de datos.
- **Normalizar las entradas** (por ejemplo, convertir correos a minúsculas y eliminar caracteres innecesarios).
- **Rechazar datos truncados** en vez de insertarlos silenciosamente.
- **Configurar la base de datos para rechazar silencios o errores automáticos**, y controlar los mensajes de error de forma segura.

## Conclusión

El ataque de truncado SQL es una técnica simple pero poderosa. Aprovechando la forma en que las bases de datos manejan los límites de longitud, un atacante puede alterar el comportamiento de inserción de datos y comprometer cuentas existentes. Este tipo de ataque demuestra por qué es vital validar cuidadosamente todos los datos de entrada, tanto en formato como en longitud, antes de almacenarlos o procesarlos.

Como profesionales de la ciberseguridad, debemos identificar estos riesgos durante auditorías o pentests, y asegurarnos de que los desarrolladores comprendan su impacto para aplicar las medidas correctivas necesarias.

---

