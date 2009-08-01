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

#include "sha.h"

word32
ROTR_32(byte n, word32 x)
{
	// Sanity check.
	assert(n < sizeof(x) * 8);

	return ((x >> n) | (x << (sizeof(x) * 8 - n)));
}

word64
ROTR_64(byte n, word64 x)
{
	// Sanity check.
	assert(n < sizeof(x) * 8);

	return ((x >> n) | (x << (sizeof(x) * 8 - n)));
}

word32
SHR_32(byte n, word32 x)
{
	// Sanity check.
	assert(n < sizeof(x) * 8);

	return (x >> n);
}

word64
SHR_64(byte n, word64 x)
{
	// Sanity check.
	assert(n < sizeof(x) * 8);

	return (x >> n);
}

word32
Ch_32(word32 x, word32 y, word32 z)
{
	return ((x & y) ^ (~x & z));
}

word64
Ch_64(word64 x, word64 y, word64 z)
{
	return ((x & y) ^ (~x & z));
}

word32
Maj_32(word32 x, word32 y, word32 z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

word64
Maj_64(word64 x, word64 y, word64 z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

word32
Sigma0_32(word32 x)
{
	return (ROTR_32(2, x) ^ ROTR_32(13, x) ^ ROTR_32(22, x));
}

word64
Sigma0_64(word64 x)
{
	return (ROTR_64(28, x) ^ ROTR_64(34, x) ^ ROTR_64(39, x));
}

word32
Sigma1_32(word32 x)
{
	return (ROTR_32(6, x) ^ ROTR_32(11, x) ^ ROTR_32(25, x));
}

word64
Sigma1_64(word64 x)
{
	return (ROTR_64(14, x) ^ ROTR_64(18, x) ^ ROTR_64(41, x));
}

word32
sigma0_32(word32 x)
{
	return (ROTR_32(7, x) ^ ROTR_32(18, x) ^ SHR_32(3, x));
}

word64
sigma0_64(word64 x)
{
	return (ROTR_64(1, x) ^ ROTR_64(8, x) ^ SHR_64(7, x));
}

word32
sigma1_32(word32 x)
{
	return (ROTR_32(17, x) ^ ROTR_32(19, x) ^ SHR_32(10, x));
}

word32
sigma1_64(word64 x)
{
	return (ROTR_64(19, x) ^ ROTR_64(61, x) ^ SHR_64(6, x));
}
