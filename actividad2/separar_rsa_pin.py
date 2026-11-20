from pathlib import Path

# Leer el flujo TCP reconstruido
archivo = Path("flujo_tcp.bin")
datos = archivo.read_bytes()

# Buscar la etiqueta RSA_PIN que identifica el bloque del PIN
etiqueta = b"RSA_PIN"
offset = datos.find(etiqueta)

# Comprobar si la etiqueta fue encontrada dentro del flujo
if offset == -1:
    print("No se encontró la etiqueta RSA_PIN.")
    exit()

# Extraer el bloque completo de 280 bytes desde la etiqueta encontrada
bloque = datos[offset:offset + 280]

# Separar los componentes del bloque RSA_PIN segun su estructura
nombre = bloque[:7]
separador = bloque[7:8]
salt = bloque[8:24]
pin_cifrado = bloque[24:280]

# Mostrar la estructura general del bloque extraido
print("=== ESTRUCTURA RSA_PIN ===")
print(f"Offset de la etiqueta: {offset}")
print(f"Etiqueta: {nombre.decode()}")
print(f"Separador: {separador.hex()}")
print(f"Tamaño total del bloque: {len(bloque)} bytes")

# Mostrar los datos correspondientes al salt
print("\n=== SALT ===")
print(f"Tamaño: {len(salt)} bytes")
print(f"Hexadecimal: {salt.hex()}")

# Mostrar los bytes correspondientes al PIN cifrado con RSA
print("\n=== PIN CIFRADO ===")
print(f"Tamaño: {len(pin_cifrado)} bytes")
print(f"Hexadecimal: {pin_cifrado.hex()}")

# Comprobar que cada componente tenga el tamaño esperado
print("\n=== VALIDACIÓN ===")
print("Salt correcto:", len(salt) == 16)
print("Cifrado RSA correcto:", len(pin_cifrado) == 256)
print("Bloque completo:", len(bloque) == 280)
