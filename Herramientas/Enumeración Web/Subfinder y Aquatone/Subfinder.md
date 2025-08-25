
---

# Guía para enumerar subdominios con Subfinder y analizar visualmente con Aquatone

## Introducción

En este documento vamos a usar `subfinder` para recolectar subdominios de un dominio objetivo y `aquatone` para obtener una visualización gráfica de los servicios que corren en ellos. Esta combinación resulta útil para reconocimiento pasivo en evaluaciones de seguridad.

## Requisitos previos

Antes de comenzar, debemos tener instaladas las siguientes herramientas:

- `subfinder`
- `aquatone`
- `chromium` o `google-chrome` (para que aquatone pueda renderizar)

También necesitaremos configurar nuestras APIs en `~/.config/subfinder/provider-config.yaml` para mejorar los resultados de Subfinder.

## Paso 1: Enumerar subdominios con Subfinder

Usamos el siguiente comando para recolectar subdominios:

```bash
subfinder -d dominio.com -o subdominios.txt
````

**Explicación:**

- `-d dominio.com`: especifica el dominio objetivo.
    
- `-o subdominios.txt`: guarda los resultados en un archivo llamado `subdominios.txt`.
    

También podemos agregar la opción `-silent` para que la salida no muestre mensajes adicionales.

```bash
subfinder -d dominio.com -silent -o subdominios.txt
```

## Paso 2: Pasar la lista de subdominios a Aquatone

Ahora usamos `aquatone` para tomar capturas de pantalla de los subdominios:

```bash
cat subdominios.txt | aquatone -out aquatone_report
```

**Explicación:**

- `cat subdominios.txt`: muestra la lista de subdominios.
    
- `| aquatone`: pasa la lista a aquatone.
    
- `-out aquatone_report`: define el directorio donde se guardará el reporte final.
    

Aquatone abrirá múltiples conexiones para detectar puertos comunes y luego generará capturas de las páginas disponibles.

## Paso 3: Revisar el reporte

Una vez completado el escaneo, navegamos al directorio `aquatone_report`:

```bash
cd aquatone_report
```

Dentro encontraremos:

- `aquatone_report.html`: archivo principal para visualizar los resultados en el navegador.
    
- Capturas y datos adicionales generados por la herramienta.
    

Abrimos el archivo con un navegador:

```bash
firefox aquatone_report.html
```

## Ejemplo práctico

Vamos a hacer una prueba con el dominio realista `example.com`:

1. Recolectamos subdominios:
    

```bash
subfinder -d example.com -silent -o subdominios.txt
```

2. Visualizamos con Aquatone:
    

```bash
cat subdominios.txt | aquatone -out informe_example
```

3. Abrimos el reporte:
    

```bash
cd informe_example
firefox aquatone_report.html
```

Con esto podremos identificar visualmente los subdominios activos, si corren servicios web, y empezar a priorizar objetivos para futuras pruebas.

## Conclusión

Hemos aprendido a integrar Subfinder y Aquatone para realizar reconocimiento pasivo y obtener una vista general rápida y visual de los subdominios y servicios disponibles. Esta técnica es especialmente útil en la fase de reconocimiento de un pentest.
