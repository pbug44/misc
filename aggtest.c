
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
/*
 * aggtest.c checks aggregate.c, outputs all networks into a /24 bitmap 
 *			and dumps it,
 *			the result is then compared with cmp, if 0 the
 *			aggregation was perfect.
 $ ./aggtest r2 > x2
 $ cmp x1 x2
 $ echo $?
 0
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ctype.h>
#include <err.h>

int
main(int argc, char *argv[])
{
	FILE *f;
	char buf[512];
	char *p;
	char *space;
	int offset, cidr, len;
	uint32_t i, j;
	in_addr_t iaddress;
	uint8_t bit;

	space = calloc(1, (1 << 24) / 8);
	if (space == NULL) {
		err(1, "calloc");
	}
	
	f = fopen(argv[1], "r");
	if (f == NULL) {
		err(1, "fopen");
	}

	while (fgets(buf, sizeof(buf), f) != NULL) {
		p = &buf[0];

		while (isspace(*p))
			p++;
		
		if (*p == '#')
			continue;

		len = strlen(buf);		
	
		if (buf[len - 1] == '\n')
			buf[len - 1] = '\0';
		len--;
		if (buf[len - 1] == '\r')
			buf[len - 1] = '\0';

		p = strchr(buf, '/');
		if (p == NULL) {
			printf("%s\n", buf);
			continue;
		}	
		
		*p = '\0';
		p++;

		cidr = atoi(p);
		iaddress = ntohl(inet_addr(buf));
		j = (1 << (32 - cidr)) / 256;
		offset = ((iaddress >> 8) / 8);
		
		for (i = 0; i < j; i++) {
			bit = ((iaddress >> 8) % 8);

                     	switch (bit) {
                        case 0:
                                *(space + offset) |= 0x80;
                                break;
                        case 1:
                                *(space + offset) |= 0x40;
                                break;
                        case 2:
                                *(space + offset) |= 0x20;
                                break;
                        case 3:
                                *(space + offset) |= 0x10;
                                break;
                        case 4:
                                *(space + offset) |= 0x8;
                                break;
                        case 5:
                                *(space + offset) |= 0x4;
                                break;
                        case 6:
                                *(space + offset) |= 0x2;
                                break;
                        case 7:
                                *(space + offset) |= 0x1;
                                break;
			}

			iaddress += 256;
			offset = (iaddress >> 8) / 8;
		}


	}

	fclose(f);

	/* dump */
	for (i = 0; i < ((1 << 24) / 8); i++) {
		if (space[i] & 0x80)
			printf(".");
		else
			printf(" ");
		if (space[i] & 0x40)
			printf(".");
		else
			printf(" ");
		if (space[i] & 0x20)
			printf(".");
		else
			printf(" ");
		if (space[i] & 0x10)
			printf(".");
		else
			printf(" ");
		if (space[i] & 0x8)
			printf(".");
		else
			printf(" ");
		if (space[i] & 0x4)
			printf(".");
		else
			printf(" ");
		if (space[i] & 0x2)
			printf(".");
		else
			printf(" ");
		if (space[i] & 0x1)
			printf(".");
		else
			printf(" ");
	}
		

	exit(0);
}
