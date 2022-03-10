# AES-GCM-SIV
Implementation of AES-GCM-SIV algorithm in C.

The purpose of this [issue \#16721](https://github.com/openssl/openssl/issues/16721) is to implement AES-GCM-SIV algorithm according to the [RFC 8452](https://datatracker.ietf.org/doc/html/rfc8452).

# How to Use

To compile the project, just use the following command at the root of the project:
```bash
make
```

Then run the executable as follows: 
```bash
./test
```

You can change the example by uncommenting one of the Makefile lines and recompile it. The examples are in the file example.h. 
```makefile
# CFLAGS += -DPT_ZEROS
# CFLAGS += -DPT_ZERO_AAD
# CFLAGS += -DPT_64
```

Finally, you can remove the compiled files with the following command:
```bash
make clean
```

# Details
## Dependencies

In order to ease the integration with OpenSSL, we have used the same structures and functions implemented in AES-GCM code.

```c++
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
```

Due to a lack of knowledge of the OpenSSL architecture (with the providers directory), we were unable to integrate our code to the project. Therefore, we have used the AES and AES-CTR functions from this repository:
[kokke / Tiny AES in C](https://github.com/kokke/tiny-AES-c)

We also used the code of the POLYVAL_Horner function created by:
[Shay-Gueron / AES-GCM-SIV](https://github.com/Shay-Gueron/AES-GCM-SIV)

These dependencies have been placed in the utils directory.

## Code

Here are the functions we have implemented: 
```c++
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
```

These functions use static functions which are:
```c++
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
```
