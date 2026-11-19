from pathlib import Path

datos = Path("flujo_tcp.bin").read_bytes()

etiqueta = b"AESGCM"
prefijo = b"AESGCM|"

offsets = []
posicion = 0

while True:
    offset = datos.find(etiqueta, posicion)

    if offset == -1:
        break

    offsets.append(offset)
    posicion = offset + len(etiqueta)

print("=== SEPARACIÓN DE MENSAJES AES-GCM ===")
print("Mensajes encontrados:", len(offsets))

for i, offset in enumerate(offsets):
    fin = offsets[i + 1] if i + 1 < len(offsets) else len(datos)
    bloque = datos[offset:fin]

    if not bloque.startswith(prefijo):
        print(f"\nMensaje {i + 1}: prefijo no válido")
        continue

    contenido = bloque[len(prefijo):]

    nonce = contenido[:12]
    tag = contenido[-16:]
    ciphertext = contenido[12:-16]

    print(f"\n=== MENSAJE {i + 1} ===")
    print("Offset:", offset)
    print("Tamaño total:", len(bloque), "bytes")
    print("Nonce:", nonce.hex())
    print("Tamaño nonce:", len(nonce), "bytes")
    print("Ciphertext:", len(ciphertext), "bytes")
    print("Tag:", tag.hex())
    print("Tamaño tag:", len(tag), "bytes")