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
 * aggregate.c - to aggregate a list of IP networks (must be sorted)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <err.h>

int class_c_to_cidr(int);
int bitboundary(int);
uint32_t ip_range(struct in_addr *, int);
void fold(struct in_addr *, int);

TAILQ_HEAD(, network) head;

struct network {
	struct in_addr address;
	int no24;
	int cidr;
	TAILQ_ENTRY(network) entries;
} *n1, *n2, *np;


/* from ipcalc.c - license there applies for this part */
/*
 * $Id: ipcalc.c,v 1.2 2006/12/04 17:06:06 pyr Exp $
 *
 * Copyright (c) 2006 Pierre-Yves Ritschard <pyr@spootnik.org>
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
#define NETM(m)         (htonl(0xffffffff << (32 - (m))))
#define NETW(n, m)      ((n) & NETM(m))
/* end of ipcalc.c */

int
main(int argc, char *argv[])
{
	FILE *f;
	char buf[512];
	char prev[512];
	char *p;
	int ch, cflag = 0;
	int len, firstrun = 0;

	struct in_addr ip, ipmask, inmask, iprange, tmp, ipcomp;
	int cidr, slash24, save;

	while ((ch = getopt(argc, argv, "c")) != -1) {
		switch (ch) {
		case 'c':
			cflag = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	memset(&prev, 0, sizeof(prev));
	TAILQ_INIT(&head);

	f = fopen(argv[0], "r");
	if (f == NULL) {
		err(1, "fopen");
	}

	while (fgets(buf, sizeof(buf), f) != NULL) {
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

		/* get the IP address/network */
		tmp.s_addr = inet_addr(buf);

		/* compare if our next address is in the calculated ip range */
		if (tmp.s_addr != iprange.s_addr) {
			slash24 = 0;
			TAILQ_FOREACH(np, &head, entries) {
				slash24 += np->no24;
				if (cflag) {
					printf("# %s/%d\n", inet_ntoa(np->address), np->cidr);
				}
			}
			
			n2 = TAILQ_FIRST(&head);
			if (n2) {
				fold(&n2->address, slash24);
			}

			while ((np = TAILQ_FIRST(&head)) != NULL) {
				TAILQ_REMOVE(&head, np, entries);
				free(np);
			}
		} 

		ip.s_addr = tmp.s_addr;

		n1 = calloc(1, sizeof(struct network));
		if (n1 == NULL)
			err(1, "calloc");

		n1->address.s_addr = ip.s_addr;

		/* get the prefixlen */
		cidr = atoi(p);	

		iprange.s_addr = ip_range(&ip, cidr);

		if (24 - cidr >= 0) {
			slash24 = (1 << (24 - cidr));
#if DEBUG
			printf("%d\n", slash24);
#endif
		}

		n1->cidr = cidr;
		n1->no24 = slash24;

		TAILQ_INSERT_TAIL(&head, n1, entries);

	}		

	slash24 = 0;
	TAILQ_FOREACH(np, &head, entries) {
		slash24 += np->no24;
		if (cflag) {
			printf("# %s/%d\n", inet_ntoa(np->address), np->cidr);
		}
	}
			
	n2 = TAILQ_FIRST(&head);
	if (n2) {
		fold(&n2->address, slash24);
	}

	fclose(f);
}


/* convert to cidr given the number of /24's */

int
class_c_to_cidr(int c)
{
	int i, cod = ~0xffffff00;
	int ret = 0;

	for (i = 0; i < c; i++)
		cod += 256;

	cod = ~cod;

	for (i = 31; (cod & (1 << i)); i--)
		ret++;

	return (++ret);
}

/* does c lie exactly on a bit?  there is probably a better way for this */

int
bitboundary(int c)
{
	uint32_t x;
	int count = 0;

	for (x = 0; x < 32; x++)
		if ((1 << x) == c)
			count++;

	if (count == 1)
		return (1);
	else
		return (0);
}
	
/* fold the network, eating up remainders */
void 
fold(struct in_addr *base, int slash24)
{
	struct in_addr iprange;
	int save;

	save = slash24;
	if (! bitboundary(slash24)) {
		while (! bitboundary(--slash24));
	}

	while (NETW(base->s_addr, class_c_to_cidr(slash24)) != base->s_addr) {
		slash24 = slash24 / 2;
	}
	printf("%s/%d\n", inet_ntoa(*base), class_c_to_cidr(slash24));

	if (save != slash24) {
		iprange.s_addr = ip_range(base, class_c_to_cidr(slash24));

		fold(&iprange, save - slash24);
	}
}


/* IP_RANGE - get the next network based on base address and prefixlen */
 
uint32_t
ip_range(struct in_addr *base, int cidr)
{
	struct in_addr ipmask, inmask, iprange;

	/* unary 0 */
	ipmask.s_addr = ~0;
	/* calculate IPv6 netmask */
	ipmask.s_addr <<= (32 - cidr);
	/* get the inverted netmask also called the hostmask */
	inmask.s_addr = ~ipmask.s_addr;

	iprange.s_addr = ntohl(base->s_addr);	
	iprange.s_addr += (inmask.s_addr + 1);

	return (htonl(iprange.s_addr));
}
