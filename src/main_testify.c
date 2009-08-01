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

#include <sys/types.h>

#include <assert.h>
#include <dlfcn.h>
#include <dirent.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sha.h"
#include "testify.h"

#define MAX_LEN(max, s)		(((max) < strlen((s))) ? strlen((s)) : max)
#define TEST_INFO		"test"
#define TEST_DIR		"obj"
#define TEST_PREFIX		"test_"
#define TEST_SUFFIX		".so"
#define TEST_SUFFIX_SEPARATOR	'.'

typedef bool (test_fcn_t)(void);

struct unit_test
{
	test_fcn_t	*test;
	const char	*name;
	const char	*summary;
};

static struct unit_test tests[] = {
	{
		.test = test_null,
		.name = "Null",
		.summary = "Trivial test that always returns true."
	},
	{
		.test = test_sha1,
		.name = "SHA-1",
		.summary = "Exercises the SHA-1 implementation."
	},
	{
		.test = test_sha224,
		.name = "SHA-224",
		.summary = "Exercises the SHA-224 implementation."
	},
	{
		.test = test_sha256,
		.name = "SHA-256",
		.summary = "Exercises the SHA-256 implementation."
	},
	{
		.test = test_sha384,
		.name = "SHA-384",
		.summary = "Exercises the SHA-384 implementation."
	},
	{
		.test = test_sha512,
		.name = "SHA-512",
		.summary = "Exercises the SHA-512 implementation."
	}
};

static const int num_tests = sizeof(tests) / sizeof(struct unit_test);

static bool
run_test(struct unit_test *test)
{
	// Sanity check.
	assert(test != NULL);

	fprintf(stderr, "Executing test %s...\n", test->name);

	return ((*test->test)());
}

static struct unit_test *
find_test(const char *name)
{
	int i;

	// Sanity check.
	assert(name != NULL);

	for (i = 0; i < num_tests; i++)
	{
		if (strcmp(tests[i].name, name) == 0)
			return (&tests[i]);
	}

	return (NULL);
}

static void
print_usage(const char *name)
{
	int i, len;

	// Sanity check.
	assert(name != NULL);

	fprintf(stderr,
		"Usage: %s [-ahl] [name ...]\n"
		"\n"
		"  -a    Run all tests.\n"
		"  -h    Display this message.\n"
		"\n"
		"The following tests have been defined:\n",
		name);

	// Determine the length of the longest test name.
	len = 0;
	for (i = 0; i < num_tests; i++)
		len = MAX_LEN(len, tests[i].name);

	// Print out the name and summary for each test.
	for (i = 0; i < num_tests; i++)
		fprintf(stderr, "\t%*s\t%s\n", len, tests[i].name,
			tests[i].summary);

	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	int failed, flag, i, num_names, passed;
	struct unit_test *test;
	char **names;
	bool aflag;

	// Parse the command-line switches.
	aflag = false;
	while ((flag = getopt(argc, argv, "ah")) != -1)
	{
		switch (flag)
		{
		case 'a':
			aflag = true;
			break;

		default:
			print_usage(argv[0]);
		}
	}

	// The remaining arguments are test names
	names = &argv[optind];
	num_names = argc - optind;

	failed = 0;
	passed = 0;
	if (aflag && num_names == 0)
	{
		// Run all tests.
		for (i = 0; i < num_tests; i++)
		{
			if (run_test(&tests[i]))
				passed++;
			else
				failed++;
		}
	}
	else if (!aflag && num_names > 0)
	{
		// Run named tests.
		for (i = 0; i < num_names; i++)
		{
			test = find_test(names[i]);
			if (test == NULL)
			{
				fprintf(stderr, "Can't find test %s.\n",
					names[i]);
				continue;
			}

			if (run_test(test))
				passed++;
			else
				failed++;
		}
	}
	else
	{
		print_usage(argv[0]);
	}

	fprintf(stderr, "%d tests passed, %d tests failed.\n", passed, failed);

	return (EXIT_SUCCESS);
}
