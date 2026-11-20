from pathlib import Path

# Leer el flujo TCP reconstruido desde el archivo binario
datos = Path("flujo_tcp.bin").read_bytes()

# Definir la etiqueta utilizada para identificar los mensajes AES-GCM
etiqueta = b"AESGCM"

# Definir el prefijo completo que debe contener cada mensaje
prefijo = b"AESGCM|"

# Lista para almacenar las posiciones de las etiquetas encontradas
offsets = []
posicion = 0

# Buscar todas las apariciones de la etiqueta dentro del flujo TCP
while True:
    offset = datos.find(etiqueta, posicion)

    # Finalizar la busqueda cuando no se encuentren mas etiquetas
    if offset == -1:
        break

    # Guardar la posicion encontrada y continuar la busqueda
    offsets.append(offset)
    posicion = offset + len(etiqueta)

# Mostrar la cantidad de mensajes encontrados
print("=== SEPARACIÓN DE MENSAJES AES-GCM ===")
print("Mensajes encontrados:", len(offsets))

# Recorrer cada mensaje encontrado para separar sus componentes
for i, offset in enumerate(offsets):

    # Determinar el final del bloque usando el inicio del siguiente mensaje
    # Si es el ultimo mensaje, se utiliza el final del flujo TCP
    fin = offsets[i + 1] if i + 1 < len(offsets) else len(datos)
    bloque = datos[offset:fin]

    # Verificar que el bloque comience con el prefijo esperado
    if not bloque.startswith(prefijo):
        print(f"\nMensaje {i + 1}: prefijo no válido")
        continue

    # Eliminar el prefijo para trabajar solamente con los datos del mensaje
    contenido = bloque[len(prefijo):]

    # Separar los componentes utilizados por AES-GCM
    # Nonce: primeros 12 bytes
    # Tag: ultimos 16 bytes
    # Ciphertext: bytes intermedios correspondientes al contenido cifrado
    nonce = contenido[:12]
    tag = contenido[-16:]
    ciphertext = contenido[12:-16]

    # Mostrar la informacion extraida de cada mensaje
    print(f"\n=== MENSAJE {i + 1} ===")
    print("Offset:", offset)
    print("Tamaño total:", len(bloque), "bytes")
    print("Nonce:", nonce.hex())
    print("Tamaño nonce:", len(nonce), "bytes")
    print("Ciphertext:", len(ciphertext), "bytes")
    print("Tag:", tag.hex())
    print("Tamaño tag:", len(tag), "bytes")
