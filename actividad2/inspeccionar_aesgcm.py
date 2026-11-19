from pathlib import Path

datos = Path("flujo_tcp.bin").read_bytes()

etiqueta = b"AESGCM"

offsets = []
posicion = 0

while True:
    offset = datos.find(etiqueta, posicion)

    if offset == -1:
        break

    offsets.append(offset)
    posicion = offset + len(etiqueta)

print("=== ESTRUCTURA DE MENSAJES AESGCM ===")
print("Cantidad de etiquetas:", len(offsets))
print("Tamaño total del flujo:", len(datos), "bytes")

for i, offset in enumerate(offsets[:5]):
    if i + 1 < len(offsets):
        fin = offsets[i + 1]
    else:
        fin = len(datos)

    bloque = datos[offset:fin]

    print(f"\n=== MENSAJE {i + 1} ===")
    print("Offset inicial:", offset)
    print("Offset final:", fin)
    print("Tamaño del bloque:", len(bloque), "bytes")
    print("Contenido hexadecimal:")
    print(bloque.hex(" "))