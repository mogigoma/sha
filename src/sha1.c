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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sha.h"

#define ROUNDS	80

static const word32 constants[] = {
	0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

static const word32 initial_hash[] = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

static word32
ROTL_32(byte n, word32 x)
{
	// Sanity check.
	assert(n < sizeof(x) * 8);

	return ((x << n) | (x >> (sizeof(x) * 8 - n)));
}

static word32
Parity_32(word32 x, word32 y, word32 z)
{
	return (x ^ y ^ z);
}


static word32
f(byte t, word32 x, word32 y, word32 z)
{
	word32 (*funcs[])(word32, word32, word32) = {
		Ch_32, Parity_32, Maj_32, Parity_32
	};

	// Sanity check.
	assert(t < ROUNDS);

	return ((*funcs[t / 20])(x, y, z));
}

static word32
K(byte t)
{
	// Sanity check.
	assert(t < ROUNDS);

	return (constants[t / 20]);
}

static bool
pad(struct sha1 *ctx)
{
	word32 index, len_b;
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
	if (!sha1_add(ctx, SHA32_BLK))
		return (false);

	// Add extra block.
	if (extra)
	{
		memcpy(&ctx->block.bytes[0], &ctx->block.bytes[SHA32_BLK],
			SHA32_BLK);
		if (!sha1_add(ctx, SHA32_BLK))
			return (false);
	}

	return (true);
}

char *
sha1(int fd)
{
	word32 bytes_left, bytes_read;
	struct sha1 ctx;
	char *hash;

	// Initialize context.
	if (!sha1_init(&ctx))
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
		if (!sha1_add(&ctx, bytes_read))
			return (NULL);
	}

	// Calculate the hash.
	if (!sha1_calc(&ctx))
		return (NULL);

	// Copy hash for caller.
	hash = strdup(ctx.hash);
	if (hash == NULL)
		warn("strdup");

	return (hash);
}

bool
sha1_init(struct sha1 *ctx)
{
	int i;

	if (ctx == NULL)
		return (false);

	// Set the initial hash value.
	for (i = 0; i < SHA1_LEN / sizeof(word32); i++)
		ctx->H[i] = initial_hash[i];

	ctx->message_len = 0;
	ctx->hash[0] = '\0';

	return (true);
}

bool
sha1_add(struct sha1 *ctx, int len)
{
	word32 a, b, c, d, e, T, W[ROUNDS];
	byte t;

	if (ctx == NULL || len > SHA32_BLK)
		return (false);

	// Last block of message needs to be specially padded.
	ctx->block_len = len;
	if (ctx->block_len < SHA32_BLK)
		return (true);

	// Prepare the message schedule.
	for (t = 0; t < ROUNDS; t++)
	{
		if (t < SHA32_SCHED)
		{
			W[t] = ntohl(ctx->block.words[t]);
		}
		else
		{
			W[t] = W[t - 3];
			W[t] ^= W[t - 8];
			W[t] ^= W[t - 14];
			W[t] ^= W[t - 16];
			W[t] = ROTL_32(1, W[t]);
		}
	}

	// Initialize the working variables.
	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];

	// Run through each round.
	for (t = 0; t < ROUNDS; t++)
	{
		T = ROTL_32(5, a) + f(t, b, c, d) + e + K(t) + W[t];
		e = d;
		d = c;
		c = ROTL_32(30, b);
		b = a;
		a = T;
	}

	// Compute the intermediate hash value.
	ctx->H[0] += a;
        ctx->H[1] += b;
        ctx->H[2] += c;
        ctx->H[3] += d;
        ctx->H[4] += e;

	// Record the processing of this block.
	ctx->message_len += ctx->block_len;
	ctx->block_len = 0;

	return (true);
}

bool
sha1_calc(struct sha1 *ctx)
{
	if (ctx == NULL)
		return (false);

	// Perform padding.
	if (!pad(ctx))
		return (false);

	// Translate the words to hex digits.
	snprintf(ctx->hash, sizeof(ctx->hash),
		"%08x%08x%08x%08x%08x",
		ctx->H[0],
		ctx->H[1],
		ctx->H[2],
		ctx->H[3],
		ctx->H[4]);

	return (true);
}
