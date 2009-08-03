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

#include "test_sums.h"
#include "testify.h"

static struct test_pair tests[] = {
	// FIPS-180-2.
	{
		"tests/fips-180-2/24-bit_message",
		"a9993e364706816aba3e25717850c26c9cd0d89d"
	},
	{
		"tests/fips-180-2/448-bit_message",
		"84983e441c3bd26ebaae4aa1f95129e5e54670f1"
	},
	{
		"tests/fips-180-2/8000000-bit_message",
		"34aa973cd4c4daa4f61eeb2bdbad27316534016f"
	},

	// Wikipedia.
	{
		"tests/wikipedia/empty",
		"da39a3ee5e6b4b0d3255bfef95601890afd80709"
	},
	{
		"tests/wikipedia/lazy_cog",
		"de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
	},
	{
		"tests/wikipedia/lazy_dog",
		"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
	}
};

static const int num_tests = sizeof(tests) / sizeof(struct test_pair);

bool
test_sha1(void)
{
	return test_sums(sha1, tests, num_tests);
}
