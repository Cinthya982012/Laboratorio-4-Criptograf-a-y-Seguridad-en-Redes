from pathlib import Path

# Leer el flujo TCP guardado desde Wireshark
archivo = Path("flujo_tcp.bin")
datos = archivo.read_bytes()

# Mostrar informacion general del archivo analizado
print(f"Archivo analizado: {archivo.name}")
print(f"Tamaño total: {len(datos)} bytes")
print("-" * 60)

# Buscar la etiqueta que identifica el bloque RSA del PIN
etiqueta = b"RSA_PIN"
posicion = datos.find(etiqueta)

# Verificar si la etiqueta RSA_PIN se encuentra dentro del flujo
if posicion == -1:
    print("No se encontró la etiqueta RSA_PIN.")
else:
    # Mostrar la posicion donde comienza la etiqueta encontrada
    print(f"Etiqueta RSA_PIN encontrada en el offset: {posicion}")

    # Extraer una porcion del flujo a partir de la etiqueta RSA_PIN
    # Se limita a 300 bytes o al tamaño disponible del archivo
    inicio = posicion
    fin = min(posicion + 300, len(datos))
    fragmento = datos[inicio:fin]

    # Mostrar el fragmento extraido en formato hexadecimal
    print("\nContenido desde RSA_PIN (hexadecimal):")
    print(fragmento.hex(" "))

    # Mostrar el contenido extraido directamente en formato bytes
    print("\nContenido desde RSA_PIN (bytes):")
    print(fragmento)

    # Definir la etiqueta que identifica los mensajes AESGCM
    etiqueta_aes = b"AESGCM"
    posiciones_aes = []
    cursor = 0

    # Buscar todas las apariciones de la etiqueta AESGCM en el flujo
    while True:
        encontrado = datos.find(etiqueta_aes, cursor)

        # Finalizar la busqueda cuando no existan mas etiquetas
        if encontrado == -1:
            break

        # Guardar la posicion de la etiqueta encontrada
        posiciones_aes.append(encontrado)

        # Continuar la busqueda desde despues de la etiqueta actual
        cursor = encontrado + len(etiqueta_aes)

    # Mostrar la cantidad total de etiquetas AESGCM encontradas
    print("\n" + "-" * 60)
    print(f"Etiquetas AESGCM encontradas: {len(posiciones_aes)}")

    # Recorrer las posiciones encontradas y mostrar su offset
    for i, pos in enumerate(posiciones_aes, start=1):
        print(f"{i}. Offset: {pos}")
