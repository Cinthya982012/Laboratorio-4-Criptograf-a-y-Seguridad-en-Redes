from pathlib import Path
import hashlib

# Leer el flujo TCP que contiene los datos capturados
datos = Path("flujo_tcp.bin").read_bytes()

# Buscar la ubicacion del bloque RSA_PIN dentro del flujo
offset = datos.find(b"RSA_PIN")

# Verificar si se encontro el bloque
if offset == -1:
    raise ValueError("No se encontró RSA_PIN")

# Extraer el bloque de datos a partir de la posicion encontrada
bloque = datos[offset:offset + 280]

# Extraer el salt utilizado para la derivacion de la clave
salt = bloque[8:24]

# PIN recuperado en el paso anterior
pin = b"4827"

# Derivacion de clave mediante Scrypt
# Se utilizan los parametros definidos para obtener una clave de 32 bytes
clave = hashlib.scrypt(
    password=pin,
    salt=salt,
    n=2**14,
    r=8,
    p=1,
    dklen=32
)

# Mostrar los resultados obtenidos durante la derivacion
print("=== DERIVACIÓN DE CLAVE SCRYPT ===")
print("PIN utilizado:", pin.decode())
print("Salt:", salt.hex())
print("Parámetros: N=16384, r=8, p=1")
print("Longitud de clave:", len(clave), "bytes")
print("Longitud de clave:", len(clave) * 8, "bits")
print("Clave AES-256 derivada:", clave.hex())

# Comprobar que la clave derivada tenga el tamaño esperado
print("\n=== VALIDACIÓN ===")
print("Clave de 32 bytes:", len(clave) == 32)
