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

enum sha_type
{
	SHA1,
	SHA224,
	SHA256,
	SHA384,
	SHA512
};

/******************************************************************************
 * 32-bit
 ******************************************************************************/
#define SHA32_BLK	(512 / 8)
#define SHA32_HASH	(256 / 8)

struct sha32
{
	enum sha_type	type;
	word32	H[SHA32_HASH / sizeof(word32)];
	union
	{
		byte	bytes[2 * SHA32_BLK / sizeof(byte)];
		word32	words[2 * SHA32_BLK / sizeof(word32)];
	} block;
	word32	block_len;
	word64	message_len;
	char	hash[SHA32_HASH * 2 + 1];
};

char	*sha1(int fd);
char	*sha224(int fd);
char	*sha256(int fd);

bool	 sha32_init(struct sha32 *ctx);
bool	 sha32_add(struct sha32 *ctx, int len);
bool	 sha32_calc(struct sha32 *ctx);

/******************************************************************************
 * 64-bit
 ******************************************************************************/
#define SHA64_BLK	(1024 / 8)
#define SHA64_HASH	(512 / 8)

struct sha64
{
	enum sha_type	type;
	word64	H[SHA64_HASH / sizeof(word64)];
	union
	{
		byte	bytes[2 * SHA64_BLK / sizeof(byte)];
		word64	words[2 * SHA64_BLK / sizeof(word64)];
	} block;
	word64	block_len;
	word64	message_len[2];
	char	hash[SHA64_HASH * 2 + 1];
};

char	*sha384(int fd);
char	*sha512(int fd);

bool	 sha64_init(struct sha64 *ctx);
bool	 sha64_add(struct sha64 *ctx, int len);
bool	 sha64_calc(struct sha64 *ctx);

#endif
