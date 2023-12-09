# signature Python example

import oqs
import time
from pprint import pprint

#######################################################################
# signature example
#######################################################################

# Imprime la versión de liboqs y liboqs-python
print("liboqs version:", oqs.oqs_version())
print("liboqs-python version:", oqs.oqs_python_version())
print("Enabled signature mechanisms:")
# Obtiene y muestra los mecanismos de firma digital habilitados actualmente
sigs = oqs.get_enabled_sig_mechanisms()
pprint(sigs, compact=True)

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
        # Imprime los detalles de la firma para el firmante
        print("\nSignature details:")
        pprint(signer.details)

        # El firmante genera su par de claves
        signer_public_key = signer.generate_keypair()

        # El firmante firma el mensaje
        # Se mide el tiempo de firmado
        inicioFirma = time.time()
        signature = signer.sign(message)
        finFirma = time.time()

        print("\nEl tiempo para la generación de la firma es:", finFirma - inicioFirma)

        # El verificador verifica la firma utilizando el mensaje, la firma y la clave pública del firmante
        # Se mide el tiempo de verificación de la firma
        inicioVerificacion =  time.time()
        is_valid = verifier.verify(message, signature, signer_public_key)
        finVerificacion =  time.time()

        print("\nEl tiempo para la verificación de la firma es:", finVerificacion - inicioVerificacion)

        print("\nEl tiempo total: firmado + verificación de firma es:",(finFirma - inicioFirma) + (finVerificacion - inicioVerificacion))

        # Imprime si la firma es válida o no
        print("\nValid signature?", is_valid)