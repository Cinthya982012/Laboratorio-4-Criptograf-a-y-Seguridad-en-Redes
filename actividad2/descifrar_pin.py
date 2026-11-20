from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Leer el flujo TCP reconstruido que contiene los datos capturados
datos = Path("flujo_tcp.bin").read_bytes()

# Buscar la etiqueta RSA_PIN dentro del flujo para localizar el bloque
offset = datos.find(b"RSA_PIN")

# Verificar si se encontro el bloque RSA_PIN
if offset == -1:
    raise ValueError("No se encontró RSA_PIN")

# Extraer el bloque de datos a partir de la posicion encontrada
bloque = datos[offset:offset + 280]

# Separar el salt y el PIN cifrado del bloque RSA_PIN
# El salt ocupa 16 bytes y el PIN cifrado se encuentra a continuacion
salt = bloque[8:24]
pin_cifrado = bloque[24:280]

# Cargar la clave privada RSA desde el archivo PEM
with open("clave_privada.pem", "rb") as archivo:
    clave_privada = serialization.load_pem_private_key(
        archivo.read(),
        password=None
    )

# Descifrar el PIN utilizando RSA-OAEP con SHA-256
# Se utiliza SHA-256 tanto para el algoritmo principal como para MGF1
pin_descifrado = clave_privada.decrypt(
    pin_cifrado,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Mostrar los resultados del proceso de descifrado
print("=== DESCIFRADO RSA ===")
print("Descifrado realizado correctamente")
print("Salt:", salt.hex())
print("PIN recuperado:", pin_descifrado.decode())
print("Longitud del PIN:", len(pin_descifrado), "bytes")
