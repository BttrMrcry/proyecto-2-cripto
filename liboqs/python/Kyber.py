# key encapsulation Python example

import oqs
import time
from pprint import pprint

#######################################################################
#KYBER example
#######################################################################

# Selecciona el mecanismo de KEM "Kyber768" y crea instancias para el cliente y el servidor
kemalg = "Kyber768"
with oqs.KeyEncapsulation(kemalg) as client:
    with oqs.KeyEncapsulation(kemalg) as server:

        # El cliente genera su par de claves  -----    ALICE
        public_key_client = client.generate_keypair()
        
        # El servidor encapsula su secreto (texto cifrado) utilizando la clave pública del cliente ----- BOB
        # Se mide el tiempo que tarda el servidor en realizar la encapsulación del secreto
        inicioBob = time.time()
        ciphertext, shared_secret_server = server.encap_secret(public_key_client)# El texto de Bob se cifra con la clave de Alice. 
                                                                                #Se regresa el texto cifrado y el secreto compartido
        finBob = time.time()

        print("\n Tiempo de encapsulamiento del secreto de Bob con la clave de Alice: ", (finBob - inicioBob)*(1000)," [ms]")

        # El cliente desencapsula el texto cifrado del servidor para obtener el secreto compartido
        # Se mide el tiempo de desencapsulamiento del texto cifrado
        inicioAlice = time.time()
        shared_secret_client = client.decap_secret(ciphertext)#Debido a que el texto de Bob se cifra con la clave de Alice, esta puede desencapsular el texto cifrado
                                                              #Se regresa el texto original de Bob (shared_secret_client)
        finAlice = time.time()

        print("\n Tiempo de desencapsulamiento del secreto de Bob utilizando la clave de Alice: ", (finAlice - inicioAlice)*(1000)," [ms]")

        print("\n Tiempo total: encapsulamiento + desencapsulamiento = ", ((finBob - inicioBob) + (finAlice - inicioAlice))*(1000)," [ms]")

        # Comprueba si los secretos compartidos coinciden
        print("\n ¿Los secretos compartidos coinciden?\n", shared_secret_client == shared_secret_server)
