from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Leer el flujo TCP que contiene los mensajes capturados
datos = Path("flujo_tcp.bin").read_bytes()

# Datos recuperados anteriormente durante el laboratorio
pin = b"4827"
salt = bytes.fromhex("1a065da01a70284041b93dd58e988907")

# Derivar la clave AES-256 mediante Scrypt
# Se utilizan los mismos parametros empleados en la derivacion anterior
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1
)

# Obtener la clave AES a partir del PIN y el salt
clave_aes = kdf.derive(pin)

print("=== DESCIFRADO DE MENSAJES AES-GCM ===")
print("Clave AES derivada:", clave_aes.hex())
print("Longitud de clave:", len(clave_aes), "bytes")

# Definir el prefijo que identifica los mensajes cifrados con AES-GCM
prefijo = b"AESGCM|"
offsets = []
posicion = 0

# Buscar todas las apariciones del prefijo dentro del flujo TCP
# Guardar las posiciones donde comienza cada mensaje
while True:
    offset = datos.find(prefijo, posicion)

    # Finalizar la busqueda cuando no se encuentren mas mensajes
    if offset == -1:
        break

    offsets.append(offset)
    posicion = offset + len(prefijo)

print("\nMensajes encontrados:", len(offsets))

# Crear el objeto AES-GCM utilizando la clave derivada
aesgcm = AESGCM(clave_aes)

# Recorrer los mensajes encontrados para procesarlos individualmente
for i, offset in enumerate(offsets):

    # Determinar el final del mensaje actual usando el inicio del siguiente
    # Si es el ultimo mensaje, utilizar el final del flujo TCP
    fin = offsets[i + 1] if i + 1 < len(offsets) else len(datos)

    # Extraer el bloque correspondiente al mensaje actual
    bloque = datos[offset:fin]
    contenido = bloque[len(prefijo):]

    # Separar los componentes necesarios para el descifrado
    # Nonce: primeros 12 bytes
    # Ciphertext: contenido cifrado
    # Tag: ultimos 16 bytes utilizados para la autenticacion
    nonce = contenido[:12]
    ciphertext = contenido[12:-16]
    tag = contenido[-16:]

    print(f"\n=== MENSAJE {i + 1} ===")

    # Intentar descifrar y verificar la autenticidad del mensaje
    try:
        mensaje_descifrado = aesgcm.decrypt(
            nonce,
            ciphertext + tag,
            None
        )

        # Mostrar el resultado si el descifrado fue exitoso
        print("Descifrado: CORRECTO")
        print("Contenido:", mensaje_descifrado)
        print("Texto:", mensaje_descifrado.decode("utf-8"))

    # Si ocurre un error indicar que el descifrado no fue exitoso
    except Exception as e:
        print("Descifrado: FALLIDO")
        print("Error:", type(e).__name__)
