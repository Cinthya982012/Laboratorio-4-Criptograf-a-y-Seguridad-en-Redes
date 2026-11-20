# Laboratorio 4 – Criptografía y Seguridad en Redes

En este repositorio se encuentran los archivos de configuración y scripts de Python utilizados durante las actividades.

## Estructura del repositorio

### Actividad 1
Contiene los archivos utilizados para la configuración y desarrollo de la primera actividad del laboratorio.

- `captura_ssh`
- `Dockerfile`
- `sshd_config`

### Actividad 2
Contiene los scripts de Python desarrollados para el análisis del flujo de red, la recuperación de información criptográfica y el procesamiento de mensajes cifrados.

- `inspeccionar_flujo.py`
- `separar_rsa_pin.py`
- `descifrar_pin.py`
- `verificar_claves.py`
- `derivar_clave.py`
- `inspeccionar_aesgcm.py`
- `separar_mensajes_aes.py`
- `descifrar_mensajes_aes.py`
- `mostrar_transacciones.py`

#### Orden de ejecución – Actividad 2

Los scripts de Python desarrollados para esta segunda actividad deben ejecutarse siguiendo el orden del proceso de análisis y recuperación de información del tráfico de red.

##### 1. Inspección del flujo TCP
`python inspeccionar_flujo.py`
##### 2. Separación de información RSA del PIN
`python separar_rsa_pin.py`
##### 3. Descifrado del PIN
`python descifrar_pin.py`
##### 4. Verificación de claves
`python verificar_claves.py`
##### 5. Derivación de la clave AES
`python derivar_clave.py`
##### 6. Inspección de mensajes AES-GCM
`python inspeccionar_aesgcm.py`
##### 7. Separación de mensajes cifrados AES
`python separar_mensajes_aes.py`
##### 8. Descifrado de mensajes AES
`python descifrar_mensajes_aes.py`
##### 9. Visualización de transacciones recuperadas
`python mostrar_transacciones.py`

## Tecnologías utilizadas

- Python 3
- Docker
- Wireshark
- Cryptografía RSA-OAEP
- Derivación de claves mediante Scrypt
- AES-256-GCM

## Propósito

El repositorio tiene como finalidad respaldar el código y los archivos utilizados durante el desarrollo de las actividades del laboratorio, complementando el informe entregado.

