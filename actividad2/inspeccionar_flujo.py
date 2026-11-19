
from pathlib import Path

# Leer el flujo TCP guardado desde Wireshark
archivo = Path("flujo_tcp.bin")
datos = archivo.read_bytes()

print(f"Archivo analizado: {archivo.name}")
print(f"Tamaño total: {len(datos)} bytes")
print("-" * 60)

# Buscar la etiqueta del mensaje RSA
etiqueta = b"RSA_PIN"
posicion = datos.find(etiqueta)

if posicion == -1:
    print("No se encontró la etiqueta RSA_PIN.")
else:
    print(f"Etiqueta RSA_PIN encontrada en el offset: {posicion}")
    
    # Mostrar una porcion del contenido que comienza en la etiqueta
    inicio = posicion
    fin = min(posicion + 300, len(datos))
    fragmento = datos[inicio:fin]

    print("\nContenido desde RSA_PIN (hexadecimal):")
    print(fragmento.hex(" "))

    print("\nContenido desde RSA_PIN (bytes):")
    print(fragmento)
    
    # Buscar etiquetas AESGCM en el flujo
    etiqueta_aes = b"AESGCM"
    posiciones_aes = []
    cursor = 0

    while True:
        encontrado = datos.find(etiqueta_aes, cursor)
        if encontrado == -1:
            break
        posiciones_aes.append(encontrado)
        cursor = encontrado + len(etiqueta_aes)

    print("\n" + "-" * 60)
    print(f"Etiquetas AESGCM encontradas: {len(posiciones_aes)}")

    for i, pos in enumerate(posiciones_aes, start=1):
        print(f"{i}. Offset: {pos}")
