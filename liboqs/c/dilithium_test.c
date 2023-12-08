#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 

#include <oqs/oqs.h>

#define MESSAGE_LEN 50

/* Cleaning up memory etc */
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len);

static OQS_STATUS dilithium3_sig(char *msg) {

#ifdef OQS_ENABLE_SIG_dilithium_3

	OQS_STATUS rc;
	uint8_t public_key[OQS_SIG_dilithium_3_length_public_key];
	uint8_t secret_key[OQS_SIG_dilithium_3_length_secret_key];
	uint8_t signature[OQS_SIG_dilithium_3_length_signature];
	size_t message_len = strlen(msg);
    uint8_t message[message_len];
	size_t signature_len;
	clock_t t;
	clock_t v;

	// let's create a random test message to sign
	//OQS_randombytes(message, message_len);

	rc = OQS_SIG_dilithium_3_keypair(public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_keypair failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_3_length_secret_key);
		return OQS_ERROR;
	}
	
    t = clock(); 

	rc = OQS_SIG_dilithium_3_sign(signature, &signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_sign failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_3_length_secret_key);
		return OQS_ERROR;
	}

	t = clock() - t; 
	double time_taken = ((double)t)/CLOCKS_PER_SEC;
	printf("Dilithium took %f seconds to sign \n", time_taken); 

	v = clock();
	rc = OQS_SIG_dilithium_3_verify(message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_verify failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_3_length_secret_key);
		return OQS_ERROR;
	}

	v = clock() - v; 
	time_taken = ((double)v)/CLOCKS_PER_SEC;
	printf("Dilithium took %f seconds to verify \n", time_taken); 
	
	printf("[example_stack] OQS_SIG_dilithium_3 operations completed.\n");
	cleanup_stack(secret_key, OQS_SIG_dilithium_3_length_secret_key);
	return OQS_SUCCESS; // success!

#else

	printf("[example_stack] OQS_SIG_dilithium_3 was not enabled at compile-time.\n");
	return OQS_ERROR;

#endif
}

int main(void) {
	FILE *file = fopen("1024KB.txt", "r");
    // Check if the file is successfully opened
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    // Read the file line by line and concatenate into a string
    char *content = NULL;
    char line[400];
    while (fgets(line, sizeof(line), file) != NULL) {
        // Allocate memory for the concatenated contents
        size_t currentLen = content ? strlen(content) : 0;
        size_t lineLen = strlen(line);
        content = realloc(content, currentLen + lineLen + 1);
        // Check for allocation failure
        if (content == NULL) {
            perror("Error allocating memory");
            fclose(file);
            return 1;
        }
        // Concatenate the current line to the content
        strcat(content, line);
    }
    // Close the file
    fclose(file);

    if (dilithium3_sig(content) == OQS_SUCCESS){
        return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
}
