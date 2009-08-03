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
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	},
	{
		"tests/fips-180-2/448-bit_message",
		"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
	},
	{
		"tests/fips-180-2/8000000-bit_message",
		"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
	},

	// Wikipedia.
	{
		"tests/wikipedia/empty",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	},
	{
		"tests/wikipedia/lazy_cog",
		"e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be"
	},
	{
		"tests/wikipedia/lazy_dog",
		"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
	}
};

static const int num_tests = sizeof(tests) / sizeof(struct test_pair);

bool
test_sha256(void)
{
	return test_sums(sha256, tests, num_tests);
}
