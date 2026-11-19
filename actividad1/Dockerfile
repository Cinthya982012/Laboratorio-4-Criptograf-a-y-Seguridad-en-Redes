
FROM ubuntu:24.04

# Actualizar e instalar servidor SSH
RUN apt-get update && \
    apt-get install -y openssh-server && \
    rm -rf /var/lib/apt/lists/*

# Crear directorio necesario para SSH
RUN mkdir -p /run/sshd

# Crear usuario para conectarnos
RUN useradd -m -s /bin/bash labuser && \
    echo 'labuser:Lab4_SSH_2026!' | chpasswd

# Generar claves del servidor
RUN ssh-keygen -A

# Copiar configuracion SSH
COPY sshd_config /etc/ssh/sshd_config

# Puerto SSH
EXPOSE 22

# Ejecutar servidor
CMD ["/usr/sbin/sshd", "-D", "-e"]
