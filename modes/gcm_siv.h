#ifndef GCM_SIV_H
#define GCM_SIV_H

#include <stddef.h>
#include <stdint.h>
#include "modes.h"

#define NONCE_LENGTH 12
#define KEY_LENGTH 16

typedef struct gcm128_context {
    /* Following 6 names follow names in GCM specification */
    union {
        uint64_t u[2];
        uint32_t d[4];
        uint8_t c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Relative position of Yi, EKi, EK0, len, Xi, H and pre-computed Htable is
     * used in some assembler modules, i.e. don't change the order!
     */
    unsigned int mres, ares;
    block128_f block;
    const void *key;
} GCM128_CONTEXT;

// CRYPTO_gcm128_siv_setiv : function that copies the IV in the ctx structure 
//      passed as a parameter. This IV is in fact the nonce entered by the user.
extern void CRYPTO_gcm128_siv_setiv(GCM128_CONTEXT *ctx, 
                                    const unsigned char *iv, size_t len);

// CRYPTO_gcm128_siv_aad : function that copies additional data into the ctx 
//      structure.
extern int CRYPTO_gcm128_siv_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
                                 size_t len);

// CRYPTO_gcm128_siv_encrypt : encrypt the plain text entered as a 'in' 
//      parameter and places the result in the 'out' parameter. Returns 0 if 
//      everything went well, -1 otherwise.
extern int CRYPTO_gcm128_siv_encrypt(GCM128_CONTEXT *ctx, 
                                     const unsigned char *in, 
                                     unsigned char *out, size_t len, 
                                     ctr128_f ctr);

// CRYPTO_gcm128_siv_decrypt : decrypt the cipher text entered as parameter 'in' 
//      and place the result in the parameter 'out'. Returns 0 if everything 
//      went well, -1 otherwise.
extern int CRYPTO_gcm128_siv_decrypt(GCM128_CONTEXT *ctx,
                                     const unsigned char *in, 
                                     unsigned char *out, size_t len, 
                                     ctr128_f ctr);

// CRYPTO_gcm128_siv_finish : compares the entered parameter tag with the tag 
//      contained in the ctx structure that was placed after encryption or 
//      decryption.
extern int CRYPTO_gcm128_siv_finish(GCM128_CONTEXT *ctx, 
                                    const unsigned char *tag, size_t len);

// CRYPTO_gcm128_siv_tag : copy the tag contained in the ctx structure, in the 
//      function’s 'tag' parameter.
extern void CRYPTO_gcm128_siv_tag(GCM128_CONTEXT *ctx, unsigned char *tag, 
                                  size_t len);

// CRYPTO_gcm128_siv_new : create a ctx structure to perform the other GCM-SIV 
//      functions.
extern GCM128_CONTEXT *CRYPTO_gcm128_siv_new(const void *key, block128_f block);

// CRYPTO_gcm128_siv_release : releases the ctx structure passed as a parameter 
//      to free memory.
extern void CRYPTO_gcm128_siv_release(GCM128_CONTEXT *ctx);

#endif