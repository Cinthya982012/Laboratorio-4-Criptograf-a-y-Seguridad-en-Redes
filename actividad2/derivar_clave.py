from pathlib import Path
import hashlib

# Leer el flujo TCP
datos = Path("flujo_tcp.bin").read_bytes()

# Localizar bloque RSA_PIN
offset = datos.find(b"RSA_PIN")

if offset == -1:
    raise ValueError("No se encontró RSA_PIN")

bloque = datos[offset:offset + 280]

# Extraer salt
salt = bloque[8:24]

# PIN recuperado en el paso anterior
pin = b"4827"

# Derivacion de clave mediante Scrypt
clave = hashlib.scrypt(
    password=pin,
    salt=salt,
    n=2**14,
    r=8,
    p=1,
    dklen=32
)

# Mostrar resultados
print("=== DERIVACIÓN DE CLAVE SCRYPT ===")
print("PIN utilizado:", pin.decode())
print("Salt:", salt.hex())
print("Parámetros: N=16384, r=8, p=1")
print("Longitud de clave:", len(clave), "bytes")
print("Longitud de clave:", len(clave) * 8, "bits")
print("Clave AES-256 derivada:", clave.hex())

print("\n=== VALIDACIÓN ===")
print("Clave de 32 bytes:", len(clave) == 32)