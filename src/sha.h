/******************************************************************************
 * Copyright (c) 2009 Matthew Anthony Kolybabi (Mak)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 ******************************************************************************/

#ifndef __SHA_H
#define __SHA_H

#include <stdbool.h>
#include <stdint.h>

typedef uint8_t byte;
typedef uint32_t word32;
typedef uint64_t word64;

/******************************************************************************
 * SHA-1
 ******************************************************************************/
#define SHA1_BLK	(512 / 8)
#define SHA1_LEN	(160 / 8)
#define SHA1_SCHED	16

struct sha1
{
	word32	H[SHA1_LEN / sizeof(word32)];
	word32	W[SHA1_SCHED];
	union
	{
		byte	bytes[2 * SHA1_BLK / sizeof(byte)];
		word32	words[2 * SHA1_BLK / sizeof(word32)];
	} block;
	word32	block_len;
	word64	message_len;
	char	hash[SHA1_LEN + 1];
};

char	*sha1(int fd);
bool	 sha1_init(struct sha1 *ctx);
bool	 sha1_add(struct sha1 *ctx, const byte *blk, int len);
bool	 sha1_calc(struct sha1 *ctx);

/******************************************************************************
 * SHA-224
 ******************************************************************************/
#define SHA224_BLK	(512 / 8)
#define SHA224_LEN	(224 / 8)

struct sha224
{
	word32	H[SHA224_LEN / sizeof(word32)];
	byte	block[SHA224_BLK];
	word32	block_len;
	word64	message_len;
	char	hash[SHA224_LEN + 1];
};

char	*sha224(int fd);
bool	 sha224_init(struct sha224 *ctx);
bool	 sha224_add(struct sha224 *ctx, const byte *blk, int len);
bool	 sha224_calc(struct sha224 *ctx);

/******************************************************************************
 * SHA-256
 ******************************************************************************/
#define SHA256_BLK	(512 / 8)
#define SHA256_LEN	(256 / 8)

struct sha256
{
	word32	H[SHA256_LEN / sizeof(word32)];
	byte	block[SHA256_BLK];
	word32	block_len;
	word64	message_len;
	char	hash[SHA256_LEN + 1];
};

char	*sha256(int fd);
bool	 sha256_init(struct sha256 *ctx);
bool	 sha256_add(struct sha256 *ctx, const byte *blk, int len);
bool	 sha256_calc(struct sha256 *ctx);

/******************************************************************************
 * SHA-384
 ******************************************************************************/
#define SHA384_BLK	(1024 / 8)
#define SHA384_LEN	(384 / 8)

struct sha384
{
	word32	H[SHA384_LEN / sizeof(word64)];
	byte	block[SHA384_BLK];
	word64	block_len;
	word64	message_len[2];
	char	hash[SHA384_LEN + 1];
};

char	*sha384(int fd);
bool	 sha384_init(struct sha384 *ctx);
bool	 sha384_add(struct sha384 *ctx, const byte *blk, int len);
bool	 sha384_calc(struct sha384 *ctx);

/******************************************************************************
 * SHA-512
 ******************************************************************************/
#define SHA512_BLK	(1024 / 8)
#define SHA512_LEN	(512 / 8)

struct sha512
{
	word32	H[SHA512_LEN / sizeof(word64)];
	byte	block[SHA512_BLK];
	word64	block_len;
	word64	message_len[2];
	char	hash[SHA512_LEN + 1];
};

char	*sha512(int fd);
bool	 sha512_init(struct sha512 *ctx);
bool	 sha512_add(struct sha512 *ctx, const byte *blk, int len);
bool	 sha512_calc(struct sha512 *ctx);

/******************************************************************************
 * Utility functions.
 ******************************************************************************/
word32	rotl32(byte n, word32 x);
word32	rotr32(byte n, word32 x);
word64	rotr64(byte n, word64 x);
word32	shr32(byte n, word32 x);
word64	shr64(byte n, word64 x);

#endif
