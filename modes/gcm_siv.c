#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "gcm_siv.h"

#define BYTE_LENGTH 8
#define TAG_LENGTH 16

typedef struct {
	unsigned char *encryption_key;
	unsigned char *tag_key;
} pair_keys;

// CRYPTO_memcmp : Function that comes from the crypto/cpuid.c directory of the 
//  	OpenSSL code.
static int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len);

// swap32_endian : changes the endian of the encoded value to 32 bits from big 
//  	endian to little endian and conversely.
static void swap32_endian(uint32_t *value);

// derive_keys : function that derives the key from a key and a nonce with the 
//  	AES algorithm by returning in 'keys' a key for encryption and a key for 
// 		data authentication.
static void derive_keys(const void *key, uint8_t nonce[NONCE_LENGTH], 
                        pair_keys *keys, block128_f block);

// CRYPTO_gcm128_siv_init : Initialize the ctx structure.
static void CRYPTO_gcm128_siv_init(GCM128_CONTEXT *ctx, const void *key, 
			                       block128_f block);

void CRYPTO_gcm128_siv_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,
                             size_t len)
{
	ctx->len.u[0] = 0;          /* AAD length */
	ctx->len.u[1] = 0;          /* message length */
	memcpy(ctx->Yi.c, iv, len);
	memset(&ctx->Yi.c[len], 0, sizeof(ctx->Yi.c) - len);
}

int CRYPTO_gcm128_siv_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
                          size_t len)
{
	if (len == 0) {
		memset(ctx->Xi.c, 0, 1);
	}
	size_t length = (len <= sizeof(ctx->Xi.c)) ? len : sizeof(ctx->Xi.c);
	memcpy(ctx->Xi.c, aad, length);
	ctx->len.u[0] = length;
	return 0;
}

int CRYPTO_gcm128_siv_encrypt(GCM128_CONTEXT *ctx, const unsigned char *in, 
			                  unsigned char *out, size_t len, ctr128_f ctr)
{
	ctx->len.u[1] = len;
	unsigned char tmp1[KEY_LENGTH + 1], tmp2[TAG_LENGTH + 1];
	memset(tmp1, 0, KEY_LENGTH + 1);
	memset(tmp2, 0, TAG_LENGTH + 1);
	pair_keys keys;
	keys.encryption_key = tmp1;
	keys.tag_key = tmp2;
	derive_keys(ctx->key, ctx->Yi.c, &keys, ctx->block);

	uint64_t len_blk[2];
	len_blk[0] = (uint64_t)(ctx->len.u[0]) * 8;
	len_blk[1] = (uint64_t)(ctx->len.u[1]) * 8;
	uint8_t S_s[TAG_LENGTH + 1];
	memset(S_s, 0, TAG_LENGTH + 1);
	Polyval_Horner(S_s, keys.tag_key, ctx->Xi.c, ctx->len.u[0]);
	Polyval_Horner(S_s, keys.tag_key, in, ctx->len.u[1]);
	Polyval_Horner(S_s, keys.tag_key, len_blk, TAG_LENGTH);

	for (size_t i = 0; i < NONCE_LENGTH; i++)	{
		S_s[i] ^= ctx->Yi.c[i];
	}
	S_s[TAG_LENGTH - 1] &= 0x7f;
	uint8_t tag[TAG_LENGTH + 1]; 
	uint8_t counter_block[TAG_LENGTH + 1];
	tag[TAG_LENGTH] = '\0';
	counter_block[TAG_LENGTH] = '\0';
	(*ctx->block) (S_s, tag, keys.encryption_key);
	memcpy(counter_block, tag, TAG_LENGTH);
	counter_block[TAG_LENGTH - 1] |= 0x80;

	(*ctr) (in, out, ctx->len.u[1], keys.encryption_key, counter_block);
	memcpy(&out[ctx->len.u[1]], tag, TAG_LENGTH);
	memcpy(ctx->Xi.c, tag, TAG_LENGTH);
	return 0;
}

int CRYPTO_gcm128_siv_decrypt(GCM128_CONTEXT *ctx, const unsigned char *in, 
							  unsigned char *out, size_t len, ctr128_f ctr)
{
	if (len == 0 || len < TAG_LENGTH)
		return 0;

	ctx->len.u[1] = len - TAG_LENGTH;
	unsigned char tmp1[KEY_LENGTH + 1], tmp2[TAG_LENGTH + 1];
	memset(tmp1, 0, KEY_LENGTH + 1);
	memset(tmp2, 0, TAG_LENGTH + 1);
	pair_keys keys;
	keys.tag_key = tmp1;
	keys.encryption_key = tmp2;
	derive_keys(ctx->key, ctx->Yi.c, &keys, ctx->block);

	uint8_t tag[TAG_LENGTH + 1]; 
	uint8_t counter_block[TAG_LENGTH + 1];
	tag[TAG_LENGTH] = '\0';
	counter_block[TAG_LENGTH] = '\0';
	memcpy(tag, &in[ctx->len.u[1]], TAG_LENGTH);
	memcpy(counter_block, tag, TAG_LENGTH);
	counter_block[TAG_LENGTH - 1] |= 0x80;

	(*ctr) (in, out, ctx->len.u[1], keys.encryption_key, counter_block);

	uint64_t len_blk[2];
	len_blk[0] = (uint64_t)(ctx->len.u[0]) * BYTE_LENGTH;
	len_blk[1] = (uint64_t)(ctx->len.u[1]) * BYTE_LENGTH;
	uint8_t S_s[TAG_LENGTH + 1];
	memset(S_s, 0, TAG_LENGTH + 1);
	Polyval_Horner(S_s, keys.tag_key, ctx->Xi.c, ctx->len.u[0]);
	Polyval_Horner(S_s, keys.tag_key, out, ctx->len.u[1]);
	Polyval_Horner(S_s, keys.tag_key, len_blk, TAG_LENGTH);

	for (size_t i = 0; i < NONCE_LENGTH; i++)	{
		S_s[i] ^= ctx->Yi.c[i];
	}
	S_s[TAG_LENGTH - 1] &= 0x7f;
	uint8_t expected_tag[TAG_LENGTH + 1];
	expected_tag[TAG_LENGTH] = '\0';

	(*ctx->block) (S_s, expected_tag, keys.encryption_key);
	memcpy(ctx->Xi.c, expected_tag, TAG_LENGTH);
	return 0;
}

int CRYPTO_gcm128_siv_finish(GCM128_CONTEXT *ctx, const unsigned char *tag,
                             size_t len) 
{
    if (tag && len <= sizeof(ctx->Xi))
        return CRYPTO_memcmp(ctx->Xi.c, tag, len);
    else
        return -1;
}

void CRYPTO_gcm128_siv_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len)
{
    CRYPTO_gcm128_siv_finish(ctx, NULL, 0);
    memcpy(tag, ctx->Xi.c,
           len <= sizeof(ctx->Xi.c) ? len : sizeof(ctx->Xi.c));
}

GCM128_CONTEXT *CRYPTO_gcm128_siv_new(const void *key, block128_f block)
{
    GCM128_CONTEXT *ret;

    if ((ret = malloc(sizeof(*ret))) != NULL)
        CRYPTO_gcm128_siv_init(ret, key, block);

    return ret;
}

void CRYPTO_gcm128_siv_release(GCM128_CONTEXT *ctx)
{
    free(ctx);
}

static void CRYPTO_gcm128_siv_init(GCM128_CONTEXT *ctx, const void *key, 
			                       block128_f block)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block = block;
    ctx->key = key;
}

static void derive_keys(const void *key, uint8_t nonce[NONCE_LENGTH], 
					    pair_keys *keys, block128_f block) 
{
	uint8_t new_nonce[BYTE_LENGTH * 2 + 1];
	memset(new_nonce, 0, BYTE_LENGTH * 2 + 1);
	memcpy(&new_nonce[BYTE_LENGTH * 2 - NONCE_LENGTH], nonce, NONCE_LENGTH);
	uint32_t counter = 0x0;
	uint8_t strcount[BYTE_LENGTH * 2 - NONCE_LENGTH + 1];
	uint8_t res_block[BYTE_LENGTH * 2 + 1];
	res_block[BYTE_LENGTH * 2] = '\0';
	size_t limit = (KEY_LENGTH / BYTE_LENGTH) + 2;
	for (uint32_t k = 0; k < limit; ++k) {
		swap32_endian(&counter);
		PUTU32(strcount, counter);
		strcount[sizeof(strcount) - 1] = '\0';
		memcpy(new_nonce, strcount, sizeof(strcount) - 1);
		(*block) (new_nonce, res_block, key);
		if (k < 2) {
			size_t len = strlen((const char *) keys->tag_key);
			memcpy(&(keys->tag_key[len]), res_block, BYTE_LENGTH);
		} else {
			size_t len = strlen((const char *) keys->encryption_key);
			memcpy(&(keys->encryption_key[len]), res_block, BYTE_LENGTH);
		}
		swap32_endian(&counter);
		++counter;
	}
}

static void swap32_endian(uint32_t *value)
{
	uint32_t tmp = *value;
	*value  = (tmp & 0x000000ff) << (BYTE_LENGTH * 3);
	*value |= (tmp & 0x0000ff00) << BYTE_LENGTH;
	*value |= (tmp & 0x00ff0000) >> BYTE_LENGTH;
	*value |= (tmp & 0xff000000) >> (BYTE_LENGTH * 3);
}

static int CRYPTO_memcmp(const void * in_a, const void * in_b, size_t len)
{
    size_t i;
    const volatile unsigned char *a = in_a;
    const volatile unsigned char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++)
        x |= (unsigned char)(a[i] ^ b[i]);

    return x;
}