
# Definición


> Un **payload** es el código que un atacante envía y ejecuta en un sistema objetivo tras explotar una vulnerabilidad, con el fin de obtener acceso o ejecutar comandos.

---

## Tipos de Payload

### **Staged**

Los payloads **staged** se dividen en múltiples etapas. Primero, se ejecuta una carga inicial mínima que luego descarga y ejecuta la carga útil completa.

### **Non-Staged**

Los payloads **non-staged** son monolíticos y contienen todo el código necesario para ejecutarse en un solo paso, sin requerir descargas adicionales.

---

## Ejemplos de uso

### **Staged Payloads**

1. **Meterpreter (Metasploit)**: `windows/meterpreter/reverse_tcp` envía un pequeño loader que luego descarga Meterpreter completo.
    
2. **Cargas pequeñas para evitar detección**: Se ejecuta un stub inicial que luego trae el payload completo.
    
3. **Mejor adaptabilidad**: Permite cambiar el payload completo sin modificar la etapa inicial.
    

### **Non-Staged Payloads**

1. **Shell reversa tradicional**: `windows/shell_reverse_tcp` ejecuta un shell sin requerir más comunicación.
    
2. **Payloads más predecibles y estables**: No dependen de múltiples fases para ejecutarse.
    
3. **Útil en entornos sin Internet**: No requiere descargar más datos, lo que lo hace ideal para entornos aislados.

---
### Sugerencias

- [Herramientas Payload](../Payload/Herramientas%20Payload.md) 
