
---

Para la instalación de la máquina virtual Tornado IA seguir los pasos como se indica en la secuencia de imágenes

![Captura](./Imágenes/vm_1.png)


![Captura](./Imágenes/vm_2.png)


![Captura](./Imágenes/vm_3.png)


![Captura](./Imágenes/vm_4.png)


![Captura](./Imágenes/vm_5.png)


![Captura](./Imágenes/vm_6.png)


![Captura](./Imágenes/vm_7.png)


![Captura](./Imágenes/vm_8.png)


![Captura](./Imágenes/vm_9.png)


![Captura](./Imágenes/vm_10.png)


![Captura](./Imágenes/vm_11.png)


![Captura](./Imágenes/vm_12.png)


![Captura](./Imágenes/vm_13.png)


![Captura](./Imágenes/vm_14.png)


![Captura](./Imágenes/vm_15.png)

Una vez este arrancando, rápidamente darle a la tecla `e` para ir a este panel y más abajo buscar esta línea y sustituir por `rw init=/bin/bash` obtener una terminal interactiva y poder configurar correctamente la interfaz de red

![Captura](./Imágenes/vm_16.png)


![Captura](./Imágenes/vm_17.png)

Podemos ver que no tiene nuestra interfaz de red por defecto

![Captura](./Imágenes/config_1.png)

Con nano cambiamos su interfaz a la nuestra, en mi caso a `ens33`

![Captura](./Imágenes/config_2.png)


![Captura](./Imágenes/config_3.png)

Por último creamos un **snapshot** de la máquina ara tener su configuración preparada por si queremos resetear
 
![Captura](./Imágenes/config_4.png)


---





























































































