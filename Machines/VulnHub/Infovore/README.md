
---

# Infovore — Machine / Scripts (README)

**Infovore** — guía y herramientas relacionadas con la máquina VulnHub *Infovore*.

> Contenido: este directorio contiene la guía de explotación paso a paso y un script de apoyo localizado en `Scripts/phpraceCondition.py`.  

---

## Estructura

```
Machines/VulnHub/Infovore/
├─ Infovore.md
├─ Imágenes/
└─ Scripts/
└─ phpraceCondition.py
````

---

## Clonar el repositorio
```bash
git clone https://github.com/metahumo/Documento_Hacker.git
cd Documento_Hacker/Machines/VulnHub/Infovore
ls Scripts
````

---

## Descargar sólo el script (sin clonar)


URL raw:

```
https://raw.githubusercontent.com/metahumo/Documento_Hacker/refs/heads/main/Machines/VulnHub/Infovore/Scripts/phpraceCondition.py
```

Con `curl`:

```bash
curl -o phpraceCondition.py "https://github.com/metahumo/Documento_Hacker/Machines/VulnHub/Infovore/Scripts/phpraceCondition.py"
chmod +x phpraceCondition.py
```

Con `wget`:

```bash
wget -O phpraceCondition.py "https://github.com/metahumo/Documento_Hacker/Machines/VulnHub/Infovore/Scripts/phpraceCondition.py"
chmod +x phpraceCondition.py
```

---

## Ejecución (resumen)

1. Edita el script y revisa los marcadores (p. ej. `<IP_Atacante>`).
2. Usa un entorno aislado.
3. Abre un listener si el payload lo requiere:

```bash
nc -lnvp 443
```

4. Ejecuta:

```bash
python3 phpraceCondition.py <objetivo> <puerto>
```

---

## Notas

* El script puede contener payloads peligrosos. Revisar y entender antes de ejecutar.
* Para pruebas sin reverse shell, elimina o modifica la parte peligrosa del payload.

---


¿Lo dejamos así o me pasas tu `<USUARIO>/<REPO>` y rama y te lo devuelvo con la URL raw exacta ya puesta?
```
