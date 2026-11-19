from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Leer el flujo TCP
datos = Path("flujo_tcp.bin").read_bytes()

# PIN y salt recuperados anteriormente
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

# Crear objeto AES-GCM
aesgcm = AESGCM(clave_aes)

# Buscar mensajes AES-GCM
prefijo = b"AESGCM|"
offsets = []
posicion = 0

while True:
    offset = datos.find(prefijo, posicion)

    if offset == -1:
        break

    offsets.append(offset)
    posicion = offset + len(prefijo)

# Lista para almacenar transacciones recuperadas
transacciones = []

# Descifrar mensajes
for i, offset in enumerate(offsets):

    fin = offsets[i + 1] if i + 1 < len(offsets) else len(datos)

    bloque = datos[offset:fin]
    contenido = bloque[len(prefijo):]

    nonce = contenido[:12]
    ciphertext = contenido[12:-16]
    tag = contenido[-16:]

    try:
        mensaje = aesgcm.decrypt(
            nonce,
            ciphertext + tag,
            None
        ).decode("utf-8")

        # Separar los campos de la transacción
        campos = mensaje.split("|")

        if len(campos) == 5:
            estado = campos[0]
            identificador = campos[1].replace("ID=", "")
            remitente = campos[2].replace("DE=", "")
            destinatario = campos[3].replace("A=", "")
            monto = campos[4].replace("MONTO=", "")

            transacciones.append({
                "id": identificador,
                "remitente": remitente,
                "destinatario": destinatario,
                "monto": monto,
                "estado": estado
            })

    except Exception:
        print(f"Mensaje {i + 1}: error en descifrado")

# Mostrar resultados
print("=== TRANSACCIONES RECUPERADAS ===")
print("Total:", len(transacciones))

for i, t in enumerate(transacciones, start=1):

    print(f"\n--- TRANSACCIÓN {i} ---")
    print("ID:", t["id"])
    print("Remitente:", t["remitente"])
    print("Destinatario:", t["destinatario"])
    print("Monto:", t["monto"])
    print("Estado:", t["estado"])