
---

# ¿Qué es el `boundary` en `multipart/form-data`?

En un pentest web, entender el funcionamiento de `boundary` en formularios con `Content-Type="multipart/form-data"` es esencial para manipular correctamente las cargas de archivos y formularios complejos.

## ¿Qué es el `boundary`?

- **Definición**: Es una cadena única que separa las distintas partes de un cuerpo de solicitud `multipart/form-data`. Actúa como delimitador entre campos y archivos en una solicitud HTTP.
  
- **Ejemplo de uso**:
  ```http
  Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
  ```

En el cuerpo de la solicitud:

```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="field1"

value1
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="example.txt"
Content-Type: text/plain

(contenido del archivo)
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

## ¿Quién define el `boundary`?

- **Automáticamente**: Si utilizas un formulario HTML con `enctype="multipart/form-data"`, el navegador genera y asigna automáticamente el valor de `boundary` en el encabezado `Content-Type` de la solicitud.
    
- **Manualmente**: Si estás construyendo la solicitud manualmente (por ejemplo, con herramientas como `curl` o en código), debes generar un valor único para `boundary` y asegurarte de que coincida en el encabezado y en los delimitadores del cuerpo de la solicitud.
    

## ¿Por qué es importante en un pentest?

- **Manipulación de solicitudes**: Al comprender cómo se estructura el `boundary`, puedes modificar o inyectar datos en solicitudes multipart para probar vulnerabilidades como la subida de archivos no deseados o la inyección de datos en campos específicos.
    
- **Evasión de filtros**: Algunos sistemas pueden filtrar ciertos caracteres o patrones. Conocer el formato del `boundary` te permite diseñar cargas útiles que eviten estos filtros.
    
- **Explotación de vulnerabilidades**: En casos de LFI (Local File Inclusion) o RCE (Remote Code Execution), entender cómo se manejan las solicitudes multipart puede ayudarte a identificar vectores de ataque adicionales.
    

## Conclusión

El `boundary` es un componente clave en las solicitudes `multipart/form-data`, y su comprensión es fundamental para realizar pruebas de penetración efectivas en aplicaciones web que manejan formularios complejos o cargas de archivos.

Para más detalles, consulta la fuente original: [Stack Overflow - ¿Qué es el boundary en multipart/form-data?](https://stackoverflow.com/questions/3508338/what-is-the-boundary-in-multipart-form-data)

---
