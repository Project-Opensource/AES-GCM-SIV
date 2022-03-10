#ifndef EXAMPLE_H
#define EXAMPLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef PT_ZEROS

/* AES key */
const unsigned char gcm_key[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00
};

/* Unique initialisation vector */
const unsigned char gcm_iv[] = {
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Example plaintext to encrypt */
const unsigned char gcm_pt[0];

/*
 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
 * which can be authenticated using the generated Tag value.
 */
const unsigned char gcm_aad[0];

const unsigned char gcm_ct[] = {
    0xdc, 0x20, 0xe2, 0xd8, 0x3f, 0x25, 0x70, 0x5b, 0xb4, 0x9e, 0x43, 0x9e, 
    0xca, 0x56, 0xde, 0x25
};

/* Expected AEAD Tag value */
const unsigned char gcm_tag[] = {
    0xdc, 0x20, 0xe2, 0xd8, 0x3f, 0x25, 0x70, 0x5b, 0xb4, 0x9e, 0x43, 0x9e, 
    0xca, 0x56, 0xde, 0x25
};

#elif PT_ZERO_AAD

/* AES key */
const unsigned char gcm_key[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00
};

/* Unique initialisation vector */
const unsigned char gcm_iv[] = {
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
};

/* Example plaintext to encrypt */
const unsigned char gcm_pt[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
 * which can be authenticated using the generated Tag value.
 */
const unsigned char gcm_aad[0];

const unsigned char gcm_ct[] = {
    0xb5, 0xd8, 0x39, 0x33, 0x0a, 0xc7, 0xb7, 0x86, 0x57, 0x87, 0x82, 0xff, 
    0xf6, 0x01, 0x3b, 0x81, 0x5b, 0x28, 0x7c, 0x22, 0x49, 0x3a, 0x36, 0x4c 
};

/* Expected AEAD Tag value */
const unsigned char gcm_tag[] = {
    0x57, 0x87, 0x82, 0xff, 0xf6, 0x01, 0x3b, 0x81, 0x5b, 0x28, 0x7c, 0x22, 
    0x49, 0x3a, 0x36, 0x4c
};

#elif PT_64
// Plaintext 64 bits

/* AES key */
const unsigned char gcm_key[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00
};

/* Unique initialisation vector */
const unsigned char gcm_iv[] = {
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Example plaintext to encrypt */
const unsigned char gcm_pt[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00
};

/*
 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
 * which can be authenticated using the generated Tag value.
 */
const unsigned char gcm_aad[] = {
    0x01
};

// Error in RFC 8452
const unsigned char gcm_ct[] = {
    0x2f, 0x5c, 0x64, 0x05, 0x9d, 0xb5, 0x5e, 0xe0, 0xfb, 0x84, 0x7e, 0xd5, 
    0x13, 0x00, 0x37, 0x46, 0x5e, 0xb9, 0xf3, 0xe8, 0xa1, 0xf9, 0xfa, 0x34, 
    0x55, 0x32, 0x3b, 0xa4, 0xf4, 0xcb, 0x8d, 0x9e, 0xd7, 0x10, 0x4d, 0x70, 
    0x19, 0x37, 0x96, 0xa2, 0xd7, 0x6e, 0x09, 0x43, 0x63, 0x1b, 0x90, 0x8b, 
    0x66, 0x9c, 0x79, 0x4a, 0x0b, 0x18, 0xb7, 0x29, 0x59, 0x22, 0x0f, 0x46, 
    0xdb, 0x0a, 0xf6, 0x79, 0xcd, 0xc4, 0x6a, 0xe4, 0x75, 0x56, 0x3d, 0xe0, 
    0x37, 0x00, 0x1e, 0xf8, 0x4a, 0xe2, 0x17, 0x44
};

/* Expected AEAD Tag value */
const unsigned char gcm_tag[] = {
    0xcd, 0xc4, 0x6a, 0xe4, 0x75, 0x56, 0x3d, 0xe0, 0x37, 0x00, 0x1e, 0xf8, 
	0x4a, 0xe2, 0x17, 0x44
};

#else

/* AES key */
const unsigned char gcm_key[] = {
    0xee, 0x8e, 0x1e, 0xd9, 0xff, 0x25, 0x40, 0xae, 0x8f, 0x2b, 0xa9, 0xf5, 
    0x0b, 0xc2, 0xf2, 0x7c
};

/* Unique initialisation vector */
const unsigned char gcm_iv[] = {
    0x75, 0x2a, 0xba, 0xd3, 0xe0, 0xaf, 0xb5, 0xf4, 0x34, 0xdc, 0x43, 0x10
};

/* Example plaintext to encrypt */
const unsigned char gcm_pt[] = {
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64
};

/*
 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
 * which can be authenticated using the generated Tag value.
 */
const unsigned char gcm_aad[] = {
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65
};

/* Expected ciphertext value */
const unsigned char gcm_ct[] = {
    0x5d, 0x34, 0x9e, 0xad, 0x17, 0x5e, 0xf6, 0xb1, 0xde, 0xf6, 0xfd, 0x4f, 
    0xbc, 0xde, 0xb7, 0xe4, 0x79, 0x3f, 0x4a, 0x1d, 0x7e, 0x4f, 0xaa, 0x70, 
    0x10, 0x0a, 0xf1
};

/* Expected AEAD Tag value */
const unsigned char gcm_tag[] = {
    0x4f, 0xbc, 0xde, 0xb7, 0xe4, 0x79, 0x3f, 0x4a, 0x1d, 0x7e, 0x4f, 0xaa, 
    0x70, 0x10, 0x0a, 0xf1
};
#endif

#endif