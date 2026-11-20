# Utilizar Ubuntu 24.04 como imagen base del contenedor
FROM ubuntu:24.04

# Actualizar los paquetes e instalar el servidor OpenSSH
# Se eliminan las listas de paquetes para reducir el tamaño de la imagen
RUN apt-get update && \
    apt-get install -y openssh-server && \
    rm -rf /var/lib/apt/lists/*

# Crear el directorio necesario para que el servicio SSH pueda ejecutarse
RUN mkdir -p /run/sshd

# Crear un usuario local para realizar la conexion SSH al contenedor
# Se asigna un directorio home y una shell Bash
# Se establece la contraseña del usuario para la autenticacion
RUN useradd -m -s /bin/bash labuser && \
    echo 'labuser:Lab4_SSH_2026!' | chpasswd

# Generar las claves de host necesarias para el funcionamiento del servidor SSH
RUN ssh-keygen -A

# Copiar el archivo de configuracion personalizado del servidor SSH al directorio de configuración de OpenSSH dentro del contenedor
COPY sshd_config /etc/ssh/sshd_config

# Indicar que el contenedor utiliza el puerto 22 para conexiones SSH
EXPOSE 22

# Ejecutar el servidor SSH en primer plano
# La opción -D evita que el proceso se ejecute en segundo plano
# La opción -e permite enviar los registros a la salida estándar
CMD ["/usr/sbin/sshd", "-D", "-e"]
