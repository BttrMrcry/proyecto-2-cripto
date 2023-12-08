/*
 * example_kem.c
 *
 * Minimal example of a Diffie-Hellman-style post-quantum key encapsulation
 * implemented in liboqs.
 *
*/

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <oqs/oqs.h>

/* Cleaning up memory etc */
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len);


OQS_STATUS kyber() {
#ifndef OQS_ENABLE_KEM_kyber_768 
	printf("[example_stack] OQS_KEM_kyber_768 was not enabled at "
	       "compile-time.\n");
	return OQS_ERROR;
#else
	uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
	uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
	uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
	uint8_t shared_secret_e[OQS_KEM_kyber_768_length_shared_secret];
	uint8_t shared_secret_d[OQS_KEM_kyber_768_length_shared_secret];
    clock_t t;

	OQS_STATUS rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
		cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_768_length_shared_secret);

		return OQS_ERROR;
	}
    t = clock();
	rc = OQS_KEM_kyber_768_encaps(ciphertext, shared_secret_e, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
		cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_768_length_shared_secret);

		return OQS_ERROR;
	}
    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC;
	printf("Kyber_768 took %f seconds to encaps \n", time_taken);

    t = clock();
	rc = OQS_KEM_kyber_768_decaps(shared_secret_d, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_kyber_768_decaps failed!\n");
		cleanup_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_768_length_shared_secret);

		return OQS_ERROR;
	}
    t = clock() - t;
    time_taken = ((double)t)/CLOCKS_PER_SEC;
	printf("Kyber_768 took %f seconds to decaps \n", time_taken);

	printf("[example_stack] OQS_KEM_kyber_768 operations completed.\n");

	return OQS_SUCCESS; // success!
#endif
}

int main(void) {
	if (kyber() == OQS_SUCCESS) {
		return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
	OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}