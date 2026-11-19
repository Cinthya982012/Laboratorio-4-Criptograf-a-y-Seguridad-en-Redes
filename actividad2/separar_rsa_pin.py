from pathlib import Path

# Leer el flujo TCP reconstruido
archivo = Path("flujo_tcp.bin")
datos = archivo.read_bytes()

# Buscar la etiqueta RSA_PIN
etiqueta = b"RSA_PIN"
offset = datos.find(etiqueta)

if offset == -1:
    print("No se encontró la etiqueta RSA_PIN.")
    exit()

# Extraer el bloque de 280 bytes
bloque = datos[offset:offset + 280]

# Separar los componentes
nombre = bloque[:7]
separador = bloque[7:8]
salt = bloque[8:24]
pin_cifrado = bloque[24:280]

print("=== ESTRUCTURA RSA_PIN ===")
print(f"Offset de la etiqueta: {offset}")
print(f"Etiqueta: {nombre.decode()}")
print(f"Separador: {separador.hex()}")
print(f"Tamaño total del bloque: {len(bloque)} bytes")

print("\n=== SALT ===")
print(f"Tamaño: {len(salt)} bytes")
print(f"Hexadecimal: {salt.hex()}")

print("\n=== PIN CIFRADO ===")
print(f"Tamaño: {len(pin_cifrado)} bytes")
print(f"Hexadecimal: {pin_cifrado.hex()}")

# Verificar tamaños esperados
print("\n=== VALIDACIÓN ===")
print("Salt correcto:", len(salt) == 16)
print("Cifrado RSA correcto:", len(pin_cifrado) == 256)
print("Bloque completo:", len(bloque) == 280)