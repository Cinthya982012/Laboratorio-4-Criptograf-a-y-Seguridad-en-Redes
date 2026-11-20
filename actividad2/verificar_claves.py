from cryptography.hazmat.primitives import serialization

# Cargar la clave privada desde el archivo PEM
with open("clave_privada.pem", "rb") as archivo:
    clave_privada = serialization.load_pem_private_key(
        archivo.read(),
        password=None
    )

# Cargar la clave publica desde el archivo PEM
with open("clave_publica.pem", "rb") as archivo:
    clave_publica = serialization.load_pem_public_key(
        archivo.read()
    )

# Mostrar informacion de la clave privada cargada
print("Clave privada cargada correctamente")
print("Tipo:", type(clave_privada).__name__)
print("Tamaño:", clave_privada.key_size, "bits")

# Mostrar informacion de la clave publica cargada
print("\nClave pública cargada correctamente")
print("Tipo:", type(clave_publica).__name__)
print("Tamaño:", clave_publica.key_size, "bits")
