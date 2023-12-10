# signature Python example

import oqs
import time
from pprint import pprint

#######################################################################
# sphincs+ example
#######################################################################

##--------------------------------------LECTURA DEL ARCHIVO 1024KB.txt

# Abre y lee el contenido del archivo '1024KB.txt'
with open('1024KB.txt', 'r') as archivo:
    clearMessage = archivo.read()
    # print("\n", clearMessage)

# Codifica el mensaje leído del archivo
message = clearMessage.encode()

# crear al firmante y al verificador con mecanismos de firma de muestra (usa el algoritmo de hashing sha2 y la variante f128)
sigalg = "SPHINCS+-SHA2-128f-simple"
# Crea instancias de firma tanto para el firmante como para el verificador
with oqs.Signature(sigalg) as signer:
    with oqs.Signature(sigalg) as verifier:
        # El firmante genera su par de claves
        signer_public_key = signer.generate_keypair()

        # El firmante firma el mensaje
        # Se mide el tiempo de firmado
        inicioFirma = time.time()
        signature = signer.sign(message)
        finFirma = time.time()

        print("\nEl tiempo para la generación de la firma es:", (finFirma - inicioFirma)*(1000)," [ms]")

        # El verificador verifica la firma utilizando el mensaje, la firma y la clave pública del firmante
        # Se mide el tiempo de verificación de la firma
        inicioVerificacion =  time.time()
        is_valid = verifier.verify(message, signature, signer_public_key)
        finVerificacion =  time.time()

        print("\nEl tiempo para la verificación de la firma es:", (finVerificacion - inicioVerificacion)*(1000)," [ms]")

        print("\nEl tiempo total: firmado + verificación de firma es:",((finFirma - inicioFirma) + (finVerificacion - inicioVerificacion))*(1000)," [ms]")

        # Imprime si la firma es válida o no
        print("\n¿La firma es válida?\n", is_valid)