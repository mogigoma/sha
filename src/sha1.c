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

#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sha.h"

#define ROUNDS	80

static const char *initial_hash[] = {
	"0x67452301",
	"0xefcdab89",
	"0x98badcfe",
	"0x10325476",
	"0xc3d2e1f0"
};

// Shared utility functions.
extern word32 rotl32(byte n, word32 x);

static word32
Ch(word32 x, word32 y, word32 z)
{
	return ((x & y) ^ (~x & z));
}

static word32
Parity(word32 x, word32 y, word32 z)
{
	return (x ^ y ^ z);
}

static word32
Maj(word32 x, word32 y, word32 z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

static word32
f(byte t, word32 x, word32 y, word32 z)
{
	// Sanity check.
	assert(t < ROUNDS);

	if (t <= 19)
		return (Ch(x, y, z));
	else if (t >= 20 && t <= 39)
		return (Parity(x, y, z));
	else if (t >= 40 && t <= 59)
		return (Maj(x, y, z));
	else
		return (Parity(x, y, z));
}

static word32
K(byte t)
{
	// Sanity check.
	assert(t < ROUNDS);

	if (t <= 19)
		return (0x5a827999);
	else if (t <= 39)
		return (0x6ed9eba1);
	else if (t <= 59)
		return (0x8f1bbcdc);
	else
		return (0xca62c1d6);
}

static word32
W(struct sha1 *ctx, byte t)
{
	word32 new_W;

	// Sanity check.
	assert(ctx != NULL);
	assert(t < ROUNDS);

	if (t < SHA1_SCHED)
	{
		new_W = ctx->block.words[t];
	}
	else
	{
		new_W = 0;
		new_W ^= ctx->W[t - 3];
		new_W ^= ctx->W[t - 8];
		new_W ^= ctx->W[t - 14];
		new_W ^= ctx->W[t - 16];
	}

	printf("[W %d] %08x\n", t, new_W);

	// Shift array to open slot for new value.
	memmove(&ctx->W[0], &ctx->W[1], sizeof(ctx->W) - sizeof(new_W));

	// Add new value.
	ctx->W[SHA1_SCHED - 1] = new_W;

	return (new_W);
}

static bool
pad(struct sha1 *ctx)
{
	byte blk[SHA1_BLK];
	bool extra_blk;
	word64 len_m;
	word32 len_b;

	// Sanity check.
	assert(ctx != NULL);

	len_b = ctx->block_len;
	len_m = ctx->message_len + len_b * 8;
	extra_blk = len_b > SHA1_BLK - sizeof(len_m) - 1;
	if (!extra_blk)
	{
		// Add trailing '1'.
		ctx->block.bytes[len_b] = (byte) (1 << 7);

		// Add final length.
		ctx->block.bytes[SHA1_BLK - 8] = 0xFF & (len_m >> 56);
		ctx->block.bytes[SHA1_BLK - 7] = 0xFF & (len_m >> 48);
		ctx->block.bytes[SHA1_BLK - 6] = 0xFF & (len_m >> 40);
		ctx->block.bytes[SHA1_BLK - 5] = 0xFF & (len_m >> 32);
		ctx->block.bytes[SHA1_BLK - 4] = 0xFF & (len_m >> 24);
		ctx->block.bytes[SHA1_BLK - 3] = 0xFF & (len_m >> 16);
		ctx->block.bytes[SHA1_BLK - 2] = 0xFF & (len_m >> 8);
		ctx->block.bytes[SHA1_BLK - 1] = 0xFF & (len_m >> 0);

		sha1_add(ctx, blk, SHA1_BLK);
	}

	return (true);
}

char *
sha1(int fd)
{
	word32 bytes_left, bytes_read;
	byte blk[SHA1_BLK];
	struct sha1 ctx;
	char *hash;

	// Initialize context.
	if (!sha1_init(&ctx))
		return (NULL);

	// Run each through each block.
	while (true)
	{
		// Initial read to fill block.
		bytes_left = SHA1_BLK;
		bytes_read = read(fd, &blk, bytes_left);

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
			bytes_read = read(fd, &blk, bytes_left);

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
		bytes_read = SHA1_BLK - bytes_left;
		if (!sha1_add(&ctx, blk, bytes_read))
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
	int i, rc;

	if (ctx == NULL)
		return (false);

	// Set the initial hash value.
	for (i = 0; i < SHA1_LEN / sizeof(word32); i++)
	{
		rc = sscanf(initial_hash[i], "%x", &ctx->H[i]);
		assert(rc == 1);
	}

	ctx->message_len = 0;
	ctx->hash[0] = '\0';

	return (true);
}

bool
sha1_add(struct sha1 *ctx, const byte *blk, int len)
{
	word32 a, b, c, d, e, T;
	byte t;

	if (ctx == NULL || len > SHA1_BLK)
		return (false);

	// Last block of message needs to be specially padded.
	ctx->block_len = len;
	memmove(ctx->block.bytes, blk, SHA1_BLK);
	if (ctx->block_len < SHA1_BLK)
	{
		memset(&ctx->block.bytes[len], 0, SHA1_BLK - len);
		return (true);
	}

	printf("--> %08x\n", ctx->block.words[0]);

	// Initialize the working variables.
	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];

	// Run through each round.
	for (t = 0; t < ROUNDS; t++)
	{
		T = rotl32(5, a) + f(t, b, c, d) + e + K(t) + W(ctx, t);
		e = d;
		d = c;
		c = rotl32(30, b);
		b = a;
		a = T;

		//printf("t = %02d: %08x\t%08x\t%08x\t%08x\t%08x\t\n", t, a, b, c, d, e);
	}

	// Compute the intermediate hash value.
	ctx->H[0] = a;
        ctx->H[1] = b;
        ctx->H[2] = c;
        ctx->H[3] = d;
        ctx->H[4] = e;

	// Record the processing of this block.
	ctx->message_len += len * 8;

	return (true);
}

bool
sha1_calc(struct sha1 *ctx)
{
	int i;

	if (ctx == NULL)
		return (false);

	// Perform padding.
	if (!pad(ctx))
		return (false);

	// Translate the words to hex digits.
	for (i = 0; i < SHA1_LEN / sizeof(word32); i++)
		sprintf(&ctx->hash[i * 8], "%08x", ctx->H[i]);

	return (true);
}
