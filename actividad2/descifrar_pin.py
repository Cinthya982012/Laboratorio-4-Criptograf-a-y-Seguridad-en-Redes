from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Leer flujo TCP reconstruido
datos = Path("flujo_tcp.bin").read_bytes()

# Buscar bloque RSA_PIN
offset = datos.find(b"RSA_PIN")

if offset == -1:
    raise ValueError("No se encontró RSA_PIN")

bloque = datos[offset:offset + 280]

# Separar salt y PIN cifrado
salt = bloque[8:24]
pin_cifrado = bloque[24:280]

# Cargar clave privada RSA
with open("clave_privada.pem", "rb") as archivo:
    clave_privada = serialization.load_pem_private_key(
        archivo.read(),
        password=None
    )

# Descifrar mediante RSA-OAEP con SHA-256
pin_descifrado = clave_privada.decrypt(
    pin_cifrado,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Mostrar resultado
print("=== DESCIFRADO RSA ===")
print("Descifrado realizado correctamente")
print("Salt:", salt.hex())
print("PIN recuperado:", pin_descifrado.decode())
print("Longitud del PIN:", len(pin_descifrado), "bytes")