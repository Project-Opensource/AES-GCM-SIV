#ifndef MODES_H
# define MODES_H

# include <stddef.h>
# include <stdint.h>

# define AES_BLOCK_SIZE 16

typedef unsigned char u8;
typedef unsigned int u32;
# define PUTU32(p,v) ((p)[0]=(u8)((v)>>24),(p)[1]=(u8)((v)>>16),(p)[2]=(u8)((v)>>8),(p)[3]=(u8)(v))
# define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))


typedef void (*block128_f) (const unsigned char in[16], unsigned char out[16], 
                            const void *key);

typedef void (*ctr128_f) (const unsigned char *in, unsigned char *out,
                          size_t blocks, const void *key,
                          const unsigned char ivec[16]);

#endif