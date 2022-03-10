#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "modes/gcm_siv.h"
#include "example.h"

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#include "utils/aes.h"

static void AES_encrypt(const unsigned char in[16], unsigned char out[16], 
                        const void *key);

static void aes_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t blocks, const void *key,
                        unsigned char ivec[16]);

static void test_function(GCM128_CONTEXT *ctx_enc, GCM128_CONTEXT *ctx_dec);

int main(void)
{
	GCM128_CONTEXT *ctx_enc = CRYPTO_gcm128_siv_new(gcm_key, 
			(block128_f) AES_encrypt);
	CRYPTO_gcm128_siv_setiv(ctx_enc, gcm_iv, sizeof(gcm_iv));
	GCM128_CONTEXT *ctx_dec = CRYPTO_gcm128_siv_new(gcm_key, 
			(block128_f) AES_encrypt);
	CRYPTO_gcm128_siv_setiv(ctx_dec, gcm_iv, sizeof(gcm_iv));

	test_function(ctx_enc, ctx_dec);

	CRYPTO_gcm128_siv_release(ctx_enc);
	CRYPTO_gcm128_siv_release(ctx_dec);
    return 0;
}

static void AES_encrypt(const unsigned char in[16],
                        unsigned char out[16], const void *key)
{
    memcpy(out, in, 16);
    struct AES_ctx aes_ctx;
    AES_init_ctx(&aes_ctx, (const uint8_t *) key);
    AES_ECB_encrypt(&aes_ctx, out);
}

static void aes_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t blocks, const void *key,
                        unsigned char ivec[16]) 
{
    memcpy(out, in, blocks);
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, (const uint8_t *) key, ivec);
    
    AES_CTR_xcrypt_buffer(&ctx, out, blocks);
}

# define print_bytes(in, len)                \
			for (size_t i = 0; i < len; ++i) \
				printf("%02x ", in[i]);      \
			printf("\n\n");	                 \

static void test_function(GCM128_CONTEXT *ctx_enc, GCM128_CONTEXT *ctx_dec)
{
	uint8_t ciphertext[sizeof(gcm_ct)];
	uint8_t plaintext[sizeof(gcm_pt)];
	uint8_t tag[AES_BLOCK_SIZE];
	uint8_t tag_calculated[AES_BLOCK_SIZE];
	printf("Plaintext:\n");
	print_bytes(gcm_pt, sizeof(gcm_pt))

	printf("Additionnal data:\n");
	print_bytes(gcm_aad, sizeof(gcm_aad))

	printf("key:\n");
	print_bytes(gcm_key, AES_BLOCK_SIZE)

	// encryption
	printf("_______Encryption_______\n\n");
	memset(ciphertext, 0, sizeof(gcm_ct));
	memset(plaintext, 0, sizeof(gcm_pt));
	CRYPTO_gcm128_siv_aad(ctx_enc, gcm_aad, sizeof(gcm_aad));
	CRYPTO_gcm128_siv_encrypt(ctx_enc, gcm_pt, ciphertext, sizeof(gcm_pt), 
		(ctr128_f) aes_ctr128_encrypt);

	printf("Ciphertext:\n");
	print_bytes(ciphertext, sizeof(ciphertext))

	CRYPTO_gcm128_siv_tag(ctx_enc, tag, sizeof(tag));
	printf("Tag:\n");
	print_bytes(tag, AES_BLOCK_SIZE)

	int is_good_ct = memcmp(gcm_ct, ciphertext, sizeof(gcm_ct));
	printf("ENCRYPTION: %s\n\n", (is_good_ct == 0) ? "CORRECT" : "WRONG");

	// decryption
	printf("_______Decryption_______\n\n");
	memset(ciphertext, 0, sizeof(gcm_ct));
	memset(plaintext, 0, sizeof(gcm_pt));
	CRYPTO_gcm128_siv_aad(ctx_dec, gcm_aad, sizeof(gcm_aad));
	CRYPTO_gcm128_siv_decrypt(ctx_dec, gcm_ct, plaintext, sizeof(gcm_ct), 
		(ctr128_f) aes_ctr128_encrypt);
	CRYPTO_gcm128_siv_tag(ctx_dec, tag_calculated, AES_BLOCK_SIZE);
	printf("Ciphertext decrypted:\n");
	print_bytes(plaintext, sizeof(gcm_pt))

	printf("Tag calculated:\n");
	print_bytes(tag_calculated, sizeof(tag_calculated))

	int is_good_pt = memcmp(gcm_pt, plaintext, sizeof(gcm_pt));
	printf("DECRYPTION: %s\n\n", (is_good_pt == 0) ? "CORRECT" : "WRONG");

	int is_good_tag = CRYPTO_gcm128_siv_finish(ctx_dec, gcm_tag, sizeof(gcm_tag));
	printf("Tag verification: %s\n\n", (is_good_tag == 0) ? "SUCCESS" : "FAILURE");
}