/*
 * Copyright (c) 2022 Peter J. Philipp <pjp@delphinusdns.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <math.h>
#include <unistd.h>

/*
 * convert latitude or longitude (as found with LOC DNS resource records)
 * to its cartesian coordinates as found with google maps 
 * -r is reverse, -f is forward and full reverse in one.
 * Much help given  after watching:
 * https://www.youtube.com/watch?v=W9kousU6AI0
 */

int
main(int argc, char *argv[])
{
	char resultbuf[512];
	char *p;
	double min, sec, result; /* minutes / 60, seconds / 3600 */
	int ch, fflag = 0, rflag = 0;

	while ((ch = getopt(argc, argv, "fr")) != -1) {
		switch (ch) {
		case 'f':
			fflag = 1;
			break;
		case 'r':
			rflag = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (rflag) {
		snprintf(resultbuf, sizeof(resultbuf), "%s", argv[0]);
		goto reverse;
	}

	if (argc != 3) {
		printf("usage %s: [degrees] [minutes] [seconds]\n", getprogname());
		exit(1);
	}

	result = atof(argv[0]) + (atof(argv[1]) / 60) + (atof(argv[2]) / 3600);

	snprintf(resultbuf, sizeof(resultbuf), "%f", result);
	printf("%s degrees\n", resultbuf);
		
	if (fflag == 0)
		exit (0);

	printf("and back...\n");

reverse:

	p = strchr(resultbuf, '.');
	if (p == NULL) {
		printf("%s 00 00\n", resultbuf);
		exit(0);
	}

	min = atof(p) * 60;
	*p = '\0';

	printf("latitude or longitude: %s ", resultbuf);
	snprintf(resultbuf, sizeof(resultbuf), "%f", min); 	
	
	p = strchr(resultbuf, '.');
	if (p == NULL) {
		printf("%s 00\n", resultbuf);
		exit(0);
	}

	sec = atof(p) * 60;
	*p = '\0';

	printf("%s ", resultbuf);

	printf("%f\n", sec);

	exit(0);
}
