#include <botan/kyber.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>
#include <botan/auto_rng.h>
#include <botan/dilithium.h>
#include <botan/hex.h>
#include <botan/sphincsplus.h>

#include <array>
#include <iostream>
#include <ctime>

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

   KyberExecution();

   DilithiumExecution(texto);

   SphincsPlusExecution(texto);

   
}

int KyberExecution() {
    const size_t shared_key_len = 32;
    const std::string kdf = "HKDF(SHA-512)";

    unsigned t0, t1;

    Botan::System_RNG rng;

    std::array<uint8_t, 16> salt;
    rng.randomize(salt);

    Botan::Kyber_PrivateKey privateKey(rng, Botan::KyberMode::Kyber768);
    auto publicKey = privateKey.public_key();

    t0 = clock();
    Botan::PK_KEM_Encryptor enc(*publicKey, kdf);

    const auto kem_result = enc.encrypt(rng, shared_key_len, salt);
    t1 = clock();

    double encTime = (double(t1-t0)/CLOCKS_PER_SEC);

    t0 = clock();
    Botan::PK_KEM_Decryptor dec(privateKey, rng, kdf);

    auto dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), shared_key_len, salt);
    t1 = clock();

    double decTime = (double(t1-t0)/CLOCKS_PER_SEC);

    if (dec_shared_key != kem_result.shared_key()) {
        std::cerr << "Shared key differ\n" << std::endl; 
    } else {
        std::cerr << "Shared keys are the same" << std::endl;
    }
    
    std::cout << "Kyber End" << std::endl;
    std::cout << "Encryption Time: " << encTime << std::endl;
    std::cout << "Decryption Time: " << decTime << std::endl;

    return 0;
}

int DilithiumExecution(char * message) {

    Botan::AutoSeeded_RNG rng;
    unsigned t1, t0;

    Botan::Dilithium_PrivateKey priv_key(rng, Botan::DilithiumMode::Dilithium4x4);
   auto signer = Botan::PK_Signer(priv_key, rng, "Randomized");
   t0 = clock();
   signer.update(message);
   std::vector<uint8_t> signature = signer.signature(rng);
   t1 = clock();
   double signTime = (double(t1-t0)/CLOCKS_PER_SEC);

   //std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);

   Botan::Dilithium_PublicKey pub_key(priv_key.public_key_bits(), Botan::DilithiumMode::Dilithium4x4);
   auto verifier = Botan::PK_Verifier(pub_key, "");
   t0 = clock();
   verifier.update(message);
   std::cout << std::endl << "is " << (verifier.check_signature(signature) ? "Valid" : "Invalid") << std::endl;
   t1 = clock();

   double verificationTime = (double(t1-t0)/CLOCKS_PER_SEC);

   std::cout << "Dilithium End" << std::endl;
   std::cout << "Sign Time: " << signTime << std::endl;
   std::cout << "Verification Time: " << verificationTime << std::endl;

   return 0;
}

int SphincsPlusExecution(char * message) {

    Botan::System_RNG rng;
    unsigned t1, t0;

    auto params = Botan::Sphincs_Parameters::create(Botan::Sphincs_Parameter_Set::Sphincs256Small, Botan::Sphincs_Hash_Type::Sha256);

    Botan::SphincsPlus_PrivateKey priv_key(rng, params);
    auto signer = Botan::PK_Signer(priv_key, rng, "Randomized");
    t0 = clock();
    signer.update(message);
    std::vector<uint8_t> signature = signer.signature(rng);
    t1 = clock();

    double signTime = (double(t1-t0)/CLOCKS_PER_SEC);

    auto verifier = Botan::PK_Verifier(*priv_key.public_key(), params.algorithm_identifier());
    t0 = clock();
    verifier.update(message);
    std::cout << std::endl << "Is " << (verifier.check_signature(signature) ? "valid" : "invalid") << std::endl;
    t1 = clock();

    double verificationTime = (double(t1-t0)/CLOCKS_PER_SEC);

    std::cout << "Sphincs+ End" << std::endl;
    std::cout << "Sign Time: " << signTime << std::endl;
    std::cout << "Verification Time: " << verificationTime << std::endl;

   return 0;
}