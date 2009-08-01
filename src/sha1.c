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

#include <stdlib.h>

#include "swash.h"

#define BLK_LEN	512;
#define ROUNDS	80;

typedef uint32_t word;

static word
Ch(word x, word y, word z)
{
	return ((x & y) ^ (~x & z));
}

static word
Parity(word x, word y, word z)
{
	return (x ^ y ^ z);
}

static word
Maj(word x, word y, word z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

static word
f(uint8_t t, word x, word y, word z)
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

static word
K(uint8_t t)
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

static word
rotl(uint8_t n, word w)
{
	// Sanity check.
	assert(n < sizeof(w) * 8);
}

static word
rotr(uint8_t n, word w)
{
	// Sanity check.
	assert(n < sizeof(w) * 8);
}

static bool
pad(block *b, uint64_t l)
{
	bool extra_blk;

	// Sanity check.
	assert(b != NULL);

	/*
	 * In the case that the message doesn't leave enough unused space at the
	 * end of the final block to store the '1' bit and the message length,
	 * we'll need to create a subsequent block.
	 */
	extra_blk = (l > BLK_LEN - 64 - 1);
	if (extra_blk)
	{
	}

	return (extra_blk);
}

char *
sha1(int fd)
{
	return (NULL);
}
