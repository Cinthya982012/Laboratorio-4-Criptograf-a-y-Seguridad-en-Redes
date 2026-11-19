from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Leer el flujo TCP
datos = Path("flujo_tcp.bin").read_bytes()

# Datos recuperados anteriormente
pin = b"4827"
salt = bytes.fromhex("1a065da01a70284041b93dd58e988907")

# Derivar la clave AES-256 mediante Scrypt
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1
)

clave_aes = kdf.derive(pin)

print("=== DESCIFRADO DE MENSAJES AES-GCM ===")
print("Clave AES derivada:", clave_aes.hex())
print("Longitud de clave:", len(clave_aes), "bytes")

# Buscar las etiquetas de los mensajes
prefijo = b"AESGCM|"
offsets = []
posicion = 0

while True:
    offset = datos.find(prefijo, posicion)

    if offset == -1:
        break

    offsets.append(offset)
    posicion = offset + len(prefijo)

print("\nMensajes encontrados:", len(offsets))

# Crear objeto AES-GCM
aesgcm = AESGCM(clave_aes)

# Procesar mensajes
for i, offset in enumerate(offsets):
    fin = offsets[i + 1] if i + 1 < len(offsets) else len(datos)

    bloque = datos[offset:fin]
    contenido = bloque[len(prefijo):]

    nonce = contenido[:12]
    ciphertext = contenido[12:-16]
    tag = contenido[-16:]

    print(f"\n=== MENSAJE {i + 1} ===")

    try:
        mensaje_descifrado = aesgcm.decrypt(
            nonce,
            ciphertext + tag,
            None
        )

        print("Descifrado: CORRECTO")
        print("Contenido:", mensaje_descifrado)
        print("Texto:", mensaje_descifrado.decode("utf-8"))

    except Exception as e:
        print("Descifrado: FALLIDO")
        print("Error:", type(e).__name__)