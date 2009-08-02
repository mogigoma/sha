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

#define ROUNDS	80
#define SCHED	16

typedef word64 word;

/******************************************************************************
 * Constants and initial values.
 ******************************************************************************/
static const word K[] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019,
	0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
	0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210,
	0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001,
	0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910,
	0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60,
	0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9,
	0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static const word H_384[] = {
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
	0x9159015a3070dd17, 0x152fecd8f70e5939,
	0x67332667ffc00b31, 0x8eb44a8768581511,
	0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

static const word H_512[] = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

/******************************************************************************
 * Utility functions.
 ******************************************************************************/
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

static void
add128(word *a, word b)
{
	// Sanity check.
	assert(a != NULL);

	a[1] += b;
	if (a[1] < b)
		a[0]++;
}

static void
shift128(word *a, word b)
{
	// Sanity check.
	assert(a != NULL);

	a[0] <<= b;
	a[0] |= a[1] >> (sizeof(word) - b);
	a[1] <<= b;
}

/******************************************************************************
 * Hashing functions.
 ******************************************************************************/
static bool
pad(struct sha64 *ctx)
{
	word index, len_b;
	word len_m[2];
	bool extra;

	// Sanity check.
	assert(ctx != NULL);

	// Determine if an extra block will be needed.
	len_b = ctx->block_len;
	extra = (SHA64_BLK < len_b + sizeof(len_m) + 1);

	// Zero all remaining space.
	memset(&ctx->block.bytes[len_b], 0, 2 * SHA64_BLK - len_b);

	// Add trailing '1'.
	ctx->block.bytes[len_b] = 0x80;

	// Add message length.
	index = (!extra) ? (1) : (2);
	len_m[0] = 0;
	len_m[1] = 0;
	add128(len_m, len_b);
	shift128(len_m, 8);
	ctx->block.bytes[index * SHA64_BLK - 16] = 0xFF & (len_m[0] >> 56);
	ctx->block.bytes[index * SHA64_BLK - 15] = 0xFF & (len_m[0] >> 48);
	ctx->block.bytes[index * SHA64_BLK - 14] = 0xFF & (len_m[0] >> 40);
	ctx->block.bytes[index * SHA64_BLK - 13] = 0xFF & (len_m[0] >> 32);
	ctx->block.bytes[index * SHA64_BLK - 12] = 0xFF & (len_m[0] >> 24);
	ctx->block.bytes[index * SHA64_BLK - 11] = 0xFF & (len_m[0] >> 16);
	ctx->block.bytes[index * SHA64_BLK - 10] = 0xFF & (len_m[0] >> 8);
	ctx->block.bytes[index * SHA64_BLK - 9] = 0xFF & (len_m[0] >> 0);
	ctx->block.bytes[index * SHA64_BLK - 8] = 0xFF & (len_m[1] >> 56);
	ctx->block.bytes[index * SHA64_BLK - 7] = 0xFF & (len_m[1] >> 48);
	ctx->block.bytes[index * SHA64_BLK - 6] = 0xFF & (len_m[1] >> 40);
	ctx->block.bytes[index * SHA64_BLK - 5] = 0xFF & (len_m[1] >> 32);
	ctx->block.bytes[index * SHA64_BLK - 4] = 0xFF & (len_m[1] >> 24);
	ctx->block.bytes[index * SHA64_BLK - 3] = 0xFF & (len_m[1] >> 16);
	ctx->block.bytes[index * SHA64_BLK - 2] = 0xFF & (len_m[1] >> 8);
	ctx->block.bytes[index * SHA64_BLK - 1] = 0xFF & (len_m[1] >> 0);

	// Add block.
	if (!sha64_add(ctx, SHA64_BLK))
		return (false);

	// Add extra block.
	if (extra)
	{
		memcpy(&ctx->block.bytes[0], &ctx->block.bytes[SHA64_BLK],
		       SHA64_BLK);
		if (!sha64_add(ctx, SHA64_BLK))
			return (false);
	}

	return (true);
}

static char *
sha64(int fd, enum sha_type type)
{
	word bytes_left, bytes_read;
	struct sha64 ctx;
	char *hash;

	if (type != SHA384 && type != SHA512)
		return (NULL);

	// Initialize context.
	ctx.type = type;
	if (!sha64_init(&ctx))
		return (NULL);

	// Run each through each block.
	while (true)
	{
		// Initial read to fill block.
		bytes_left = SHA64_BLK;
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
		bytes_read = SHA64_BLK - bytes_left;
		if (!sha64_add(&ctx, bytes_read))
			return (NULL);
	}

	// Calculate the hash.
	if (!sha64_calc(&ctx))
		return (NULL);

	// Copy hash for caller.
	hash = strdup(ctx.hash);
	if (hash == NULL)
		warn("strdup");

	return (hash);
}

char *
sha384(int fd)
{
	return (sha64(fd, SHA384));
}

char *
sha512(int fd)
{
	return (sha64(fd, SHA512));
}

bool
sha64_init(struct sha64 *ctx)
{
	const word *H;
	int i, num;

	if (ctx == NULL)
		return (false);

	// Set the initial hash value.
	switch (ctx->type)
	{
	case SHA224:
		H = H_384;
		num = sizeof(H_384) / sizeof(word);
		break;

	case SHA512:
		H = H_512;
		num = sizeof(H_512) / sizeof(word);
		break;

	default:
		return (false);
	}

	for (i = 0; i < num; i++)
		ctx->H[i] = H[i];

	ctx->message_len[0] = 0;
	ctx->message_len[1] = 0;
	ctx->hash[0] = '\0';

	return (true);
}

bool
sha64_add(struct sha64 *ctx, int len)
{
	word a, b, c, d, e, f, g, h, T1, T2, W[ROUNDS];
	byte t;

	if (ctx == NULL || (ctx->type != SHA384 && ctx->type != SHA512) ||
	    len > SHA64_BLK)
		return (false);

	// Last block of message needs to be specially padded.
	ctx->block_len = len;
	if (ctx->block_len < SHA64_BLK)
		return (true);

	// Prepare the message schedule.
	for (t = 0; t < ROUNDS; t++)
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
	for (t = 0; t < ROUNDS; t++)
	{
		T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
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

	// Record the processing of this block.
	ctx->message_len[1] += ctx->block_len;
	if (ctx->message_len[1] < ctx->block_len)
		ctx->message_len[0]++;
	ctx->message_len[0] += ctx->block_len;

	ctx->block_len = 0;

	return (true);
}

bool
sha64_calc(struct sha64 *ctx)
{
	if (ctx == NULL)
		return (false);

	// Perform padding.
	if (!pad(ctx))
		return (false);

	// Translate the words to hex digits.
	switch (ctx->type)
	{
	case SHA384:
		snprintf(ctx->hash, sizeof(ctx->hash),
			 "%016lx%016lx%016lx%016lx%016lx%016lx",
			 ctx->H[0],
			 ctx->H[1],
			 ctx->H[2],
			 ctx->H[3],
			 ctx->H[4],
			 ctx->H[5]);
		break;

	case SHA512:
		snprintf(ctx->hash, sizeof(ctx->hash),
			 "%016lx%016lx%016lx%016lx%016lx%016lx%016lx%016lx",
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
