from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Leer el flujo TCP reconstruido que contiene los mensajes cifrados
datos = Path("flujo_tcp.bin").read_bytes()

# PIN y salt recuperados anteriormente durante el laboratorio
pin = b"4827"
salt = bytes.fromhex("1a065da01a70284041b93dd58e988907")

# Derivar la clave AES-256 mediante Scrypt
# Se utilizan los parametros definidos para recuperar la misma clave AES
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1
)

# Obtener la clave AES a partir del PIN y el salt
clave_aes = kdf.derive(pin)

# Crear el objeto AES-GCM utilizando la clave derivada
aesgcm = AESGCM(clave_aes)

# Definir el prefijo que identifica los mensajes AES-GCM
prefijo = b"AESGCM|"
offsets = []
posicion = 0

# Buscar todas las posiciones donde comienza un mensaje AES-GCM
while True:
    offset = datos.find(prefijo, posicion)

    # Finalizar la busqueda cuando no se encuentren mas mensajes
    if offset == -1:
        break

    # Guardar el offset encontrado y continuar desde la siguiente posicion
    offsets.append(offset)
    posicion = offset + len(prefijo)

# Lista para almacenar las transacciones recuperadas y sus campos
transacciones = []

# Recorrer los mensajes encontrados para realizar el descifrado
for i, offset in enumerate(offsets):

    # Determinar el final del mensaje actual
    # Se utiliza el inicio del siguiente mensaje o el final del flujo
    fin = offsets[i + 1] if i + 1 < len(offsets) else len(datos)

    # Extraer el bloque correspondiente al mensaje actual
    bloque = datos[offset:fin]
    contenido = bloque[len(prefijo):]

    # Separar los componentes necesarios para AES-GCM
    # Nonce: primeros 12 bytes
    # Ciphertext: contenido cifrado
    # Tag: ultimos 16 bytes para verificar la autenticidad
    nonce = contenido[:12]
    ciphertext = contenido[12:-16]
    tag = contenido[-16:]

    # Intentar descifrar el mensaje y convertirlo a texto
    try:
        mensaje = aesgcm.decrypt(
            nonce,
            ciphertext + tag,
            None
        ).decode("utf-8")

        # Separar los campos de la transaccion utilizando el caracter |
        campos = mensaje.split("|")

        # Verificar que el mensaje contenga los cinco campos esperados
        if len(campos) == 5:
            estado = campos[0]
            identificador = campos[1].replace("ID=", "")
            remitente = campos[2].replace("DE=", "")
            destinatario = campos[3].replace("A=", "")
            monto = campos[4].replace("MONTO=", "")

            # Guardar los datos de la transaccion en la lista
            transacciones.append({
                "id": identificador,
                "remitente": remitente,
                "destinatario": destinatario,
                "monto": monto,
                "estado": estado
            })

    # Mostrar un mensaje si ocurre un error durante el descifrado
    except Exception:
        print(f"Mensaje {i + 1}: error en descifrado")

# Mostrar la cantidad total de transacciones recuperadas
print("=== TRANSACCIONES RECUPERADAS ===")
print("Total:", len(transacciones))

# Recorrer la lista y mostrar los datos de cada transaccion
for i, t in enumerate(transacciones, start=1):

    print(f"\n--- TRANSACCIÓN {i} ---")
    print("ID:", t["id"])
    print("Remitente:", t["remitente"])
    print("Destinatario:", t["destinatario"])
    print("Monto:", t["monto"])
    print("Estado:", t["estado"])
