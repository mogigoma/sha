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
		"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
	},
	{
		"tests/fips-180-2/448-bit_message",
		"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
	},
	{
		"tests/fips-180-2/8000000-bit_message",
		"20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
	},

	// Wikipedia.
	{
		"tests/wikipedia/empty",
		"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
	},
	{
		"tests/wikipedia/lazy_cog",
		"fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b"
	},
	{
		"tests/wikipedia/lazy_dog",
		"730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"
	}
};

static const int num_tests = sizeof(tests) / sizeof(struct test_pair);

bool
test_sha224(void)
{
	return test_sums(sha224, tests, num_tests);
}
