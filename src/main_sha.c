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
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sha.h"

static void
usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s mode [file]\n\n"
		"Calculates the message digest of a file or stream.\n"
		"Valid modes are: 1, 224, 256, 384, and 512.\n"
		"If no filename is given, STDIN is read.\n",
		name);

	exit(EXIT_FAILURE);
}

int
main(int argc, const char **argv)
{
	const char *filename;
	int fd, i, type;
	char *hash;

	// Ensure proper comand line.
	if (argc < 2)
		usage(argv[0]);
	type = atoi(argv[1]);

	// Handle STDIN.
	if (argc == 2)
	{
		filename = "-";
		fd = STDIN_FILENO;
		argc++;
	}

	// Run through each file.
	for (i = 2; i < argc; i++)
	{
		// Open file.
		if (filename == NULL)
		{
			filename = argv[i];
			fd = open(filename, O_RDONLY);
			if (fd < 0)
				err(EXIT_FAILURE, "open");
		}

		// Calculate the message digest.
		switch (type)
		{
		case 1:
			hash = sha1(fd);
			break;

		case 224:
			hash = sha224(fd);
			break;

		case 256:
			hash = sha256(fd);
			break;

		case 384:
			hash = sha384(fd);
			break;

		case 512:
			hash = sha512(fd);
			break;

		default:
			usage(argv[0]);
		}

		if (hash == NULL)
			errx(EXIT_FAILURE, "Couldn't calculate hash.");

		// Print the message digest.
		printf("%s  %s\n", hash, filename);

		// Clean up.
		filename = NULL;
		free(hash);
		close(fd);
	}

	return (EXIT_SUCCESS);
}
