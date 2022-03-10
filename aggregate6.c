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
 * aggregate6.c - to aggregate a list of IPv6 networks 
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
#include <ctype.h>
#include <endian.h>

int numlinks_to_cidr(uint64_t);
int bitboundary(uint64_t);
uint64_t highestbit(uint64_t);
uint64_t ip_range(uint64_t *base, uint64_t cidr);
void fold(uint64_t *, uint64_t);

TAILQ_HEAD(, network) head;

struct network {
	struct in6_addr address;
	uint64_t no64;
	uint64_t cidr;
	TAILQ_ENTRY(network) entries;
} *n1, *n2, *np;


#define NETM(m)         (be64toh(0xffffffffffffffffULL << (64 - (m))))
#define NETW(n, m)      ((n) & NETM(m))

int
main(int argc, char *argv[])
{
	FILE *f;
	char buf[512];
	char ip6[INET6_ADDRSTRLEN];
	char *p;
	int ch, cflag = 0;
	int len, firstrun = 0;

	uint64_t ip, ipmask, inmask, iprange, ipcomp, *tmp64;
	struct in6_addr tmp;
	uint64_t cidr, slash64, save;

	while ((ch = getopt(argc, argv, "c")) != -1) {
		switch (ch) {
		case 'c':
			cflag = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	TAILQ_INIT(&head);

	f = fopen(argv[0], "r");
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

		/* get the IP address/network */
		inet_pton(AF_INET6, buf, &tmp);
		tmp64 = (uint64_t *)&tmp;

		/* compare if our next address is in the calculated ip range */
		if (memcmp(tmp64, &iprange, sizeof(iprange)) != 0) {
			slash64 = 0;
			TAILQ_FOREACH(np, &head, entries) {
				slash64 += np->no64;
				if (cflag) {
					inet_ntop(AF_INET6, &np->address, ip6, sizeof(ip6));
					printf("# %s/%llu\n", ip6, np->cidr);
				}
			}
			
			n2 = TAILQ_FIRST(&head);
			if (n2) {
				fold((uint64_t *)&n2->address, slash64);
			}

			while ((np = TAILQ_FIRST(&head)) != NULL) {
				TAILQ_REMOVE(&head, np, entries);
				free(np);
			}
		} 

		memcpy(&ip, tmp64, sizeof(ip));

		n1 = calloc(1, sizeof(struct network));
		if (n1 == NULL)
			err(1, "calloc");

		memset(&n1->address, 0, sizeof(struct in6_addr));
		memcpy((char *)&n1->address, (char *)&ip, sizeof(ip));

		/* get the prefixlen */
		cidr = atoll(p);	

		iprange = ip_range(&ip, cidr);
		if (64 - cidr >= 0) {
			slash64 = (1ULL << (64 - cidr));
		}

		n1->cidr = cidr;
		n1->no64 = slash64;

		TAILQ_INSERT_TAIL(&head, n1, entries);

	}		

	slash64 = 0;
	TAILQ_FOREACH(np, &head, entries) {
		slash64 += np->no64;
		if (cflag) {
			inet_ntop(AF_INET6, &np->address, ip6, sizeof(ip6));
			printf("# %s/%llu\n", ip6, np->cidr);
		}
	}
			
	n2 = TAILQ_FIRST(&head);
	if (n2) {
		fold((uint64_t *)&n2->address, slash64);
	}

	fclose(f);

	exit(0);
}


/* convert to cidr given the number of /64's */

int
numlinks_to_cidr(uint64_t c)
{
	uint64_t test64;
	int i;

	for (i = 0; i < 64; i++) {
		test64 = (1ULL << (63 - i));
		if (c == test64)
			return (i + 1);
	}
	
	return (0);	
}

uint64_t
highestbit(uint64_t c)
{
	uint64_t x;
	
	for (x = 63; x >= 0; x--) {
		if ((c & (1ULL << x)) == (1ULL << x))
			return ((1ULL << x));
	}

	return (0);
}


/* does c lie exactly on a bit?  there is probably a better way for this */

int
bitboundary(uint64_t c)
{
	uint64_t x;
	uint64_t count = 0;

	for (x = 0; x < 64; x++)
		if ((1ULL << x) == c)
			count++;

	if (count == 1)
		return (1);
	else
		return (0);
}
	
/* fold the network, eating up remainders */
void 
fold(uint64_t *base, uint64_t slash64)
{
	char dest[INET6_ADDRSTRLEN];
	struct in6_addr ia6;
	uint64_t iprange;
	uint64_t save;

	save = slash64;
	if (! bitboundary(slash64)) {
		slash64 = highestbit(slash64);
	}

	while (NETW(*base, numlinks_to_cidr(slash64)) != *base) {
		slash64 = slash64 / 2;
	}
	memset(&ia6, 0, sizeof(ia6));
	memcpy(&ia6, base, sizeof(uint64_t));
	inet_ntop(AF_INET6, &ia6, dest, sizeof(dest));	
	printf("%s/%d\n", dest, numlinks_to_cidr(slash64));

	if (save != slash64) {
		iprange = ip_range(base, numlinks_to_cidr(slash64));

		fold(&iprange, save - slash64);
	}
}


/* IP_RANGE - get the next network based on base address and prefixlen */
 
uint64_t
ip_range(uint64_t *base, uint64_t cidr)
{
	uint64_t ipmask, inmask, iprange;

	/* unary 0 */
	ipmask = ~0ULL;
	/* calculate IPv6 netmask */
	ipmask <<= ((128 - cidr) - 64);
	/* get the inverted netmask also called the hostmask */
	inmask = ~ipmask;

	iprange = be64toh(*base);	
	iprange += (inmask + 1);

	return (htobe64(iprange));
}
