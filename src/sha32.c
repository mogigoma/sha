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

#include <arpa/inet.h>

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sha.h"

#define ROUNDS_SHA1	80
#define ROUNDS_SHA2	64
#define SCHED		(SHA32_BLK / sizeof(word32))

typedef word32 word;

/******************************************************************************
 * Constants and initial values.
 ******************************************************************************/
static const word K_1[] = {
	0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

static const word K_2[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,

	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,

	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,

	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,

	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,

	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,

	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,

	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const word H_1[] = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

static const word H_224[] = {
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

static const word H_256[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/******************************************************************************
 * Utility functions.
 ******************************************************************************/
static word
ROTL(byte n, word x)
{
	// Sanity check.
	assert(n < sizeof(x) * 8);

	return ((x << n) | (x >> (sizeof(x) * 8 - n)));
}

static word
ROTR(byte n, word x)
{
	// Sanity check.
	assert(n < sizeof(x) * 8);

	return ((x >> n) | (x << (sizeof(x) * 8 - n)));
}

static word
SHR(byte n, word x)
{
	// Sanity check.
	assert(n < sizeof(x) * 8);

	return (x >> n);
}

static word
Ch(word x, word y, word z)
{
	return ((x & y) ^ (~x & z));
}

static word
Maj(word x, word y, word z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

static word
Sigma0(word x)
{
	return (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x));
}

static word
Sigma1(word x)
{
	return (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x));
}

static word
sigma0(word x)
{
	return (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x));
}

static word
sigma1(word x)
{
	return (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x));
}

static word
Parity(word x, word y, word z)
{
	return (x ^ y ^ z);
}

/******************************************************************************
 * Hashing functions.
 ******************************************************************************/
static bool
pad(struct sha32 *ctx)
{
	word index, len_b;
	word64 len_m;
	bool extra;

	// Sanity check.
	assert(ctx != NULL);

	// Determine if an extra block will be needed.
	len_b = ctx->block_len;
	len_m = (ctx->message_len + len_b) * 8;
	extra = (SHA32_BLK < len_b + sizeof(len_m) + 1);

	// Zero all remaining space.
	memset(&ctx->block.bytes[len_b], 0, 2 * SHA32_BLK - len_b);

	// Add trailing '1'.
	ctx->block.bytes[len_b] = 0x80;

	// Add message length.
	index = (!extra) ? (1) : (2);
	ctx->block.bytes[index * SHA32_BLK - 8] = 0xFF & (len_m >> 56);
	ctx->block.bytes[index * SHA32_BLK - 7] = 0xFF & (len_m >> 48);
	ctx->block.bytes[index * SHA32_BLK - 6] = 0xFF & (len_m >> 40);
	ctx->block.bytes[index * SHA32_BLK - 5] = 0xFF & (len_m >> 32);
	ctx->block.bytes[index * SHA32_BLK - 4] = 0xFF & (len_m >> 24);
	ctx->block.bytes[index * SHA32_BLK - 3] = 0xFF & (len_m >> 16);
	ctx->block.bytes[index * SHA32_BLK - 2] = 0xFF & (len_m >> 8);
	ctx->block.bytes[index * SHA32_BLK - 1] = 0xFF & (len_m >> 0);

	// Add block.
	if (!sha32_add(ctx, SHA32_BLK))
		return (false);

	// Add extra block.
	if (extra)
	{
		memcpy(&ctx->block.bytes[0], &ctx->block.bytes[SHA32_BLK],
		       SHA32_BLK);
		if (!sha32_add(ctx, SHA32_BLK))
			return (false);
	}

	return (true);
}

static void
hash1(struct sha32 *ctx)
{
	word a, b, c, d, e, T, W[ROUNDS_SHA1];
	word (*f[])(word, word, word) = {
		Ch, Parity, Maj, Parity
	};
	byte t;

	// Sanity check.
	assert(ctx != NULL);

	// Prepare the message schedule.
	for (t = 0; t < ROUNDS_SHA1; t++)
	{
		if (t < SCHED)
		{
			W[t] = ntohl(ctx->block.words[t]);
		}
		else
		{
			W[t] = W[t - 3];
			W[t] ^= W[t - 8];
			W[t] ^= W[t - 14];
			W[t] ^= W[t - 16];
			W[t] = ROTL(1, W[t]);
		}
	}

	// Initialize the working variables.
	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];

	// Run through each round.
	for (t = 0; t < ROUNDS_SHA1; t++)
	{
		T = ROTL(5, a) + (*f[t / 20])(b, c, d) + e + K_1[t / 20] + W[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
	}

	// Compute the intermediate hash value.
	ctx->H[0] += a;
        ctx->H[1] += b;
        ctx->H[2] += c;
        ctx->H[3] += d;
        ctx->H[4] += e;
}

static void
hash2(struct sha32 *ctx)
{
	word32 a, b, c, d, e, f, g, h, T1, T2, W[ROUNDS_SHA2];
	byte t;

	// Prepare the message schedule.
	for (t = 0; t < ROUNDS_SHA2; t++)
	{
		if (t < SCHED)
		{
			W[t] = ntohl(ctx->block.words[t]);
		}
		else
		{
			W[t] = 0;
			W[t] += sigma1(W[t - 2]);
			W[t] += W[t - 7];
			W[t] += sigma0(W[t - 15]);
			W[t] += W[t - 16];
		}
	}

	// Initialize the working variables.
	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];
	f = ctx->H[5];
	g = ctx->H[6];
	h = ctx->H[7];

	// Run through each round.
	for (t = 0; t < ROUNDS_SHA2; t++)
	{
		T1 = h + Sigma1(e) + Ch(e, f, g) + K_2[t] + W[t];
		T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	// Compute the intermediate hash value.
	ctx->H[0] += a;
        ctx->H[1] += b;
        ctx->H[2] += c;
        ctx->H[3] += d;
        ctx->H[4] += e;
        ctx->H[5] += f;
        ctx->H[6] += g;
        ctx->H[7] += h;
}

static char *
sha32(int fd, enum sha_type type)
{
	word bytes_left, bytes_read;
	struct sha32 ctx;
	char *hash;

	if (type != SHA1 && type != SHA224 && type != SHA256)
		return (NULL);

	// Initialize context.
	ctx.type = type;
	if (!sha32_init(&ctx))
		return (NULL);

	// Run each through each block.
	while (true)
	{
		// Initial read to fill block.
		bytes_left = SHA32_BLK;
		bytes_read = read(fd, ctx.block.bytes, bytes_left);

		// End of file.
		if (bytes_read == 0)
			break;

		// Read error.
		if (bytes_read < 0)
		{
			warn("read");
			return (NULL);
		}

		// Keep trying to fill block if not yet full.
		bytes_left -= bytes_read;
		while (bytes_left > 0)
		{
			bytes_read = read(fd, ctx.block.bytes, bytes_left);

			// End of file.
			if (bytes_read == 0)
				break;

			// Read error.
			if (bytes_read < 0)
			{
				warn("read");
				return (NULL);
			}

			bytes_left -= bytes_read;
		}

		// Run block through.
		bytes_read = SHA32_BLK - bytes_left;
		if (!sha32_add(&ctx, bytes_read))
			return (NULL);
	}

	// Calculate the hash.
	if (!sha32_calc(&ctx))
		return (NULL);

	// Copy hash for caller.
	hash = strdup(ctx.hash);
	if (hash == NULL)
		warn("strdup");

	return (hash);
}

char *
sha1(int fd)
{
	return (sha32(fd, SHA1));
}

char *
sha224(int fd)
{
	return (sha32(fd, SHA224));
}

char *
sha256(int fd)
{
	return (sha32(fd, SHA256));
}

bool
sha32_init(struct sha32 *ctx)
{
	const word *H;
	int i, num;

	if (ctx == NULL)
		return (false);

	// Set the initial hash value.
	switch (ctx->type)
	{
	case SHA1:
		H = H_1;
		num = sizeof(H_1) / sizeof(word);
		break;

	case SHA224:
		H = H_224;
		num = sizeof(H_224) / sizeof(word);
		break;

	case SHA256:
		H = H_256;
		num = sizeof(H_256) / sizeof(word);
		break;

	default:
		return (false);
	}

	for (i = 0; i < num; i++)
		ctx->H[i] = H[i];

	ctx->message_len = 0;
	ctx->hash[0] = '\0';

	return (true);
}

bool
sha32_add(struct sha32 *ctx, int len)
{
	if (ctx == NULL || len > SHA32_BLK)
		return (false);

	// Last block of message needs to be specially padded.
	ctx->block_len = len;
	if (ctx->block_len < SHA32_BLK)
		return (true);

	// Set the initial hash value.
	switch (ctx->type)
	{
	case SHA1:
		hash1(ctx);
		break;

	case SHA224:
	case SHA256:
		hash2(ctx);
		break;

	default:
		return (false);
	}

	// Record the processing of this block.
	ctx->message_len += ctx->block_len;
	ctx->block_len = 0;

	return (true);
}

bool
sha32_calc(struct sha32 *ctx)
{
	if (ctx == NULL)
		return (false);

	// Perform padding.
	if (!pad(ctx))
		return (false);

	// Translate the words to hex digits.
	switch (ctx->type)
	{
	case SHA1:
		snprintf(ctx->hash, sizeof(ctx->hash),
			 "%08x%08x%08x%08x%08x",
			 ctx->H[0],
			 ctx->H[1],
			 ctx->H[2],
			 ctx->H[3],
			 ctx->H[4]);
		break;

	case SHA224:
		snprintf(ctx->hash, sizeof(ctx->hash),
			 "%08x%08x%08x%08x%08x%08x%08x",
			 ctx->H[0],
			 ctx->H[1],
			 ctx->H[2],
			 ctx->H[3],
			 ctx->H[4],
			 ctx->H[5],
			 ctx->H[6]);
		break;

	case SHA256:
		snprintf(ctx->hash, sizeof(ctx->hash),
			 "%08x%08x%08x%08x%08x%08x%08x%08x",
			 ctx->H[0],
			 ctx->H[1],
			 ctx->H[2],
			 ctx->H[3],
			 ctx->H[4],
			 ctx->H[5],
			 ctx->H[6],
			 ctx->H[7]);
		break;

	default:
		return (false);
	}

	return (true);
}
