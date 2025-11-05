import sys
import binascii
import base64

from Cryptodome.Cipher import DES, DES3, AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

# iv:= "Inicial Vector" o "Vector inicial".

def decipherInicialInput(message: str, name: str = "valor") -> bytes:
    message = message.strip()
    if message.startswith("HEX "):
        return binascii.unhexlify(message[4:].strip()) # Descifra en Hexa lol
    elif message.startswith("B64 "):
        return base64.b64decode(message[4:].strip(), validate=True) # Descifra en B64 lol
    else:
        return message.encode("utf-8") 

def bytesToHexa(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def blockSize(algorithm: str) -> int:
    if algorithm in ("DES", "3DES"):
        return 8  
    else:
        return 16

def cipherKey(userKey: bytes, algorithm: str) -> bytes:
    # DES: 8 bytes, AES-256: 32 bytes, 3DES: 16 o 24 bytes.
    if algorithm == "DES":
        need = 8
        key = (userKey + get_random_bytes(max(0, need - len(userKey))))[:need]
        return key
    elif algorithm == "AES":
        need = 32
        key = (userKey + get_random_bytes(max(0, need - len(userKey))))[:need]
        return key
    elif algorithm == "3DES":
        if len(userKey) <= 16:
            target = 16
        elif len(userKey) <= 24:
            target = 24
        else:
            target = 24
            key = (userKey + get_random_bytes(max(0, target - len(userKey))))[:target] # Con esto nos aseguramos que si la key es menor a los bytes pedidos entonces esta se complete.
            key = DES3.adjust_key_parity(key)
            DES3.new(key, DES3.MODE_ECB)
        return key
    else:
        print(" Jugad@r, no se logro cifrar nada, intentalo nuevamente.")

def createCipher(algorithm: str, key: bytes, iv: bytes, for_encrypt=True):
    # CBC 
    if algorithm == "DES":
        return DES.new(key, DES.MODE_CBC, iv=iv)
    elif algorithm == "3DES":
        return DES3.new(key, DES3.MODE_CBC, iv=iv)
    elif algorithm == "AES":
        return AES.new(key, AES.MODE_CBC, iv=iv)
    else:
        print(" Jugad@r, hay un algoritmo inválido.")

def selectAlgorithm() -> str:
    while True:
        choice = input(" Bienvenido jugad@r al laboratorio 4 de Criptografía, ¿Con cúal algoritmo deseas cifrar? \n 1. DES \n 2. 3DES \n 3. AES-256 \n ").strip()
        if choice == "1":
            return "DES"
        if choice == "2":
            return "3DES"
        if choice == "3":
            return "AES"
        print(" Opción inválida, intente nuevamente jugad@r.")

def cipherOrDecipher() -> str:
    while True:
        a = input(" Jugad@r, si quieres Cifrar, ingresa 'E', si quieres descifrar, ingresa 'D':\n").strip().upper()
        if a in ("E", "D"):
            return a
        print(" Opción inválida, intente nuevamente jugad@r solo usando E o D.\n")


def viewKeyIv(algorithm: str) -> tuple[bytes, bytes]:
    blockSize = blockSize(algorithm)
    if algorithm == "DES":
        key_hint = "8 bytes."
        iv_hint  = "8 bytes."
    elif algorithm == "3DES":
        key_hint = "16 o 24 bytes." # Depende del tamaño de la key
        iv_hint  = "8 bytes."
    else:  # AES-256
        key_hint = "32 bytes."
        iv_hint  = "16 bytes."

    print(f" Jugad@r, ingrese los siguentes datos para poder encriptar un mensaje en {algorithm} que usted desee:")
    print(" Puede ingresar la clave en texto plano. \n Si desea ingresar la clave en Hexadecimal, indiquelo con 'HEX ' seguido de su clave. \n Si desea ingresar la clave en Base64 indiquelo con 'B64 ' seguido de su clave.")
    inicialKey = decipherInicialInput(input(), "key")
    key = cipherKey(inicialKey, algorithm)

    print(f" Su clave cifrada en Hexadecimal es {bytesToHexa(key)}.")

    print(f"\n Ingrese el IV (Vector Inicial) de {iv_hint}")
    print(" Puede ingresar la clave en texto plano. \n Si desea ingresar la clave en Hexadecimal, indiquelo con 'HEX ' seguido de su clave. \n Si desea ingresar la clave en Base64 indiquelo con 'B64 ' seguido de su clave.")
    
    iv = decipherInicialInput(input(), "iv")
    need_iv = blockSize
    if len(iv) != need_iv:
        print(f" El IV no fue ingresado correctamente, ya que necesitan {need_iv} bloques para que {algorithm} funcione correctamente.")
    return key, iv

def main():
    algorithm = selectAlgorithm()
    CorD = cipherOrDecipher()
    key, iv = viewKeyIv(algorithm)
    blockSize = blockSize(algorithm)

    if CorD == "E": #Cifrar
        print(" Ingrese la palabra a cifrar \n")
        text = input().encode("utf-8")

        cipher = createCipher(algorithm, key, iv, for_encrypt=True)
        cipherText = cipher.encrypt(pad(text, blockSize))
        print(f"\n Texto encriptado: {bytesToHexa(cipherText)}")

        # Descifrado para comprobar
        decipher = createCipher(algorithm, key, iv, for_encrypt=False)
        recov = unpad(decipher.decrypt(cipherText), blockSize)
        print(f" Texto descifrado: {recov.decode('utf-8')}")
        print(f" Texto en Hexadecimal: {bytesToHexa(recov)}")

    else:  # Descifrar
        print(" Ingrese el cifrado en Hexadecimal \n")
        cipherTextHex = input().strip()

        cipherText = binascii.unhexlify(cipherTextHex)
        cipher = createCipher(algorithm, key, iv, for_encrypt=False)
        message = unpad(cipher.decrypt(cipherText), blockSize)

        print(f" Texto descifrado: {message.decode('utf-8')}")
        print(f" Texto en Hexadecimal: {bytesToHexa(message)}")

if __name__ == "__main__":
    main()
