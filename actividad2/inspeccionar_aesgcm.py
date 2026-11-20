from pathlib import Path

# Leer el flujo TCP reconstruido desde el archivo binario
datos = Path("flujo_tcp.bin").read_bytes()

# Definir la etiqueta utilizada para identificar los mensajes AES-GCM
etiqueta = b"AESGCM"

# Lista para almacenar las posiciones donde se encuentra cada etiqueta
offsets = []
posicion = 0

# Buscar todas las apariciones de la etiqueta dentro del flujo
while True:
    offset = datos.find(etiqueta, posicion)

    # Finalizar la busqueda cuando no se encuentren mas etiquetas
    if offset == -1:
        break

    # Guardar la posicion encontrada y continuar la busqueda
    offsets.append(offset)
    posicion = offset + len(etiqueta)

# Mostrar informacion general sobre la estructura de los mensajes encontrados
print("=== ESTRUCTURA DE MENSAJES AESGCM ===")
print("Cantidad de etiquetas:", len(offsets))
print("Tamaño total del flujo:", len(datos), "bytes")

# Inspeccionar los primeros cinco mensajes encontrados
for i, offset in enumerate(offsets[:5]):

    # Determinar el final del bloque utilizando el inicio del siguiente mensaje
    # Si no existe otro mensaje, se utiliza el final del flujo
    if i + 1 < len(offsets):
        fin = offsets[i + 1]
    else:
        fin = len(datos)

    # Extraer el bloque correspondiente al mensaje actual
    bloque = datos[offset:fin]

    # Mostrar informacion sobre la ubicacion y tamaño del bloque
    print(f"\n=== MENSAJE {i + 1} ===")
    print("Offset inicial:", offset)
    print("Offset final:", fin)
    print("Tamaño del bloque:", len(bloque), "bytes")

    # Mostrar el contenido del bloque en formato hexadecimal
    print("Contenido hexadecimal:")
    print(bloque.hex(" "))
