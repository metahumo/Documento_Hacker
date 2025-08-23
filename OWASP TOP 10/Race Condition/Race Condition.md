# Condiciones de Carrera (Race Condition)

Las condiciones de carrera son una vulnerabilidad que se presenta cuando dos o más procesos o hilos acceden simultáneamente a un recurso compartido sin un control adecuado de sincronización. Esto puede generar resultados inesperados, errores de lógica o incluso abrir la puerta a ataques serios si un atacante logra aprovechar esta condición.

Desde el punto de vista de la ciberseguridad ofensiva, estudiar y entender las condiciones de carrera nos permite identificar escenarios en los que un sistema puede ser manipulado para ejecutar acciones fuera del flujo previsto, lo cual es especialmente relevante en sistemas que gestionan archivos, permisos, transacciones o cualquier tipo de recurso compartido.

## ¿Qué ocurre exactamente en una condición de carrera?

Cuando no existe una sincronización adecuada entre procesos o hilos, la ejecución paralela puede derivar en resultados indeterminados. El orden en el que se accede o modifica un recurso afecta directamente a la lógica del sistema. Esto es crítico cuando hablamos de operaciones sensibles como cambios de privilegios, modificación de archivos o validación de identidades.

## Ejemplo práctico

Supongamos una aplicación web que permite a los usuarios transferir fondos desde su cuenta bancaria. El flujo lógico típico es:

1. El usuario hace clic en "Transferir".
2. La aplicación revisa si tiene saldo suficiente.
3. Si lo tiene, descuenta el saldo y realiza la transferencia.

En un ataque de condición de carrera, podemos automatizar múltiples peticiones simultáneas en el punto 1. Si el sistema no sincroniza correctamente el acceso al saldo, es posible ejecutar múltiples transferencias antes de que el sistema actualice el estado real de la cuenta. Esto permite transferir más dinero del que se dispone, explotando la lógica vulnerable de concurrencia.

Podríamos probar este comportamiento con herramientas como `Burp Suite` (funcionalidad Intruder o Turbo Intruder) o mediante un script en Python con múltiples hilos o procesos lanzando peticiones POST concurrentes hacia la misma operación.

## Caso real: CVE-2019-6111 en OpenSSH

Un caso real de condición de carrera se identificó en OpenSSH (CVE-2019-6111). El problema estaba relacionado con la forma en que el cliente SCP (Secure Copy Protocol) validaba los nombres de los archivos enviados por el servidor. Mediante un ataque de condición de carrera, un servidor malicioso podía sobrescribir archivos arbitrarios en la máquina del cliente sin su conocimiento. Esto fue posible porque la validación del nombre del archivo y la operación de escritura no estaban correctamente sincronizadas.

Este caso pone en evidencia cómo una simple operación de lectura/escritura puede ser manipulada por un atacante si no se implementan controles de concurrencia adecuados.

## Medidas de mitigación

Como profesionales o aspirantes a profesionales de ciberseguridad, debemos reconocer que la prevención de condiciones de carrera es principalmente responsabilidad del desarrollo seguro. Algunas estrategias clave incluyen:

- Implementar bloqueos (locks) adecuados cuando se accede a recursos compartidos.
- Usar semáforos o mutexes para garantizar que solo un proceso acceda al recurso crítico en un momento dado.
- Diseñar la lógica de negocio para que no dependa de múltiples operaciones separadas (por ejemplo, validar y actuar en una misma transacción atómica).
- Emplear funciones de sistema o bases de datos que garanticen atomicidad.

## Conclusión

Las condiciones de carrera representan una clase de vulnerabilidad muchas veces ignorada, pero con un potencial de explotación considerable. A través de ejemplos prácticos y casos reales, comprendemos que una mala gestión de la concurrencia puede derivar en fallos graves de seguridad. Como parte de nuestra formación, debemos identificar y simular este tipo de escenarios para entender cómo prevenirlos, explotarlos de forma controlada en entornos de prueba y fortalecer la seguridad de los sistemas.

---
