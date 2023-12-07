#include <botan/kyber.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>
#include <botan/auto_rng.h>
#include <botan/dilithium.h>
#include <botan/hex.h>
#include <botan/sphincsplus.h>

#include <array>
#include <iostream>

int DilithiumExecution(char *);
int KyberExecution();
int SphincsPlusExecution(char *);

int main(){
    FILE * archivo;
   long medida;
   char * texto;

   archivo = fopen("1024KB.txt", "r");

   fseek(archivo, 0, SEEK_END);
   medida = ftell(archivo);
   rewind(archivo);

   texto = (char*)malloc(sizeof(char)*medida);

   fread(texto, medida+1, 1, archivo);
   fclose(archivo);

   DilithiumExecution(texto);

   SphincsPlusExecution(texto);

   
}

int KyberExecution() {
    const size_t shared_key_len = 32;
    const std::string kdf = "HKDF(SHA-512)";

    Botan::System_RNG rng;

    std::array<uint8_t, 16> salt;
    rng.randomize(salt);

    Botan::Kyber_PrivateKey privateKey(rng, Botan::KyberMode::Kyber768);
    auto publicKey = privateKey.public_key();

    Botan::PK_KEM_Encryptor enc(*publicKey, kdf);

    const auto kem_result = enc.encrypt(rng, shared_key_len, salt);

    Botan::PK_KEM_Decryptor dec(privateKey, rng, kdf);

    auto dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), shared_key_len, salt);

    if (dec_shared_key != kem_result.shared_key()) {
        std::cerr << "Shared key differ\n";
        return 1;
    } else {
        std::cerr << "Shared keys are the same";
        return 0;
    }
}

int DilithiumExecution(char * message) {

    Botan::AutoSeeded_RNG rng;

    Botan::Dilithium_PrivateKey priv_key(rng, Botan::DilithiumMode::Dilithium4x4);
   auto signer = Botan::PK_Signer(priv_key, rng, "Randomized");
   signer.update(message);
   std::vector<uint8_t> signature = signer.signature(rng);

   //std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);

   Botan::Dilithium_PublicKey pub_key(priv_key.public_key_bits(), Botan::DilithiumMode::Dilithium4x4);
   auto verifier = Botan::PK_Verifier(pub_key, "");
   verifier.update(message);
   std::cout << std::endl << "is " << (verifier.check_signature(signature) ? "valid" : "invalid") << std::endl;

   return 0;
}

int SphincsPlusExecution(char * message) {

    Botan::System_RNG rng;

    auto params = Botan::Sphincs_Parameters::create(Botan::Sphincs_Parameter_Set::Sphincs256Small, Botan::Sphincs_Hash_Type::Sha256);

    Botan::SphincsPlus_PrivateKey priv_key(rng, params);
    auto signer = Botan::PK_Signer(priv_key, rng, "Randomized");
    signer.update(message);
    std::vector<uint8_t> signature = signer.signature(rng);

    auto verifier = Botan::PK_Verifier(*priv_key.public_key(), params.algorithm_identifier());
    verifier.update(message);
    std::cout << std::endl << "is " << (verifier.check_signature(signature) ? "valid" : "invalid") << std::endl;

   return 0;
}