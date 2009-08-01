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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sha.h"

#define ROUNDS	80

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

static bool
pad(byte *b, uint64_t l)
{
	bool extra_blk;

	// Sanity check.
	assert(b != NULL);

	/*
	 * In the case that the message doesn't leave enough unused space at the
	 * end of the final block to store the '1' bit and the message length,
	 * we'll need to create a subsequent block.
	 */
	extra_blk = (l > SHA1_BLK - 64 - 1);
	if (extra_blk)
	{
	}

	return (extra_blk);
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
	if (ctx == NULL)
		return (false);

	ctx->message_len = 0;
	ctx->hash[0] = '\0';

	return (true);
}

bool
sha1_add(struct sha1 *ctx, byte *blk, int len)
{
	if (ctx == NULL)
		return (false);

	return (true);
}

bool
sha1_calc(struct sha1 *ctx)
{
	if (ctx == NULL)
		return (false);

	ctx->hash[0] = 'T';
	ctx->hash[1] = 'E';
	ctx->hash[2] = 'S';
	ctx->hash[3] = 'T';
	ctx->hash[4] = '\0';

	return (true);
}
