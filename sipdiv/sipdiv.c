/* 
 * Copyright (c) 2022-2024 Peter J. Philipp
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/ethertypes.h>

#include <netinet/in.h>
#define _KERNEL 1
#include <netinet/ip.h>
#undef _KERNEL
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>

#include <ctype.h>


SLIST_HEAD(, sipdata) head;

struct sipdata {
	uint8_t flags;
#define SIP_DIV_FLAG_HEADER	0x1
#define SIP_DIV_FLAG_BODY	0x2
#define SIP_DIV_FLAG_SHORTFORM	0x4
#define SIP_DIV_FLAG_COMPACT	0x8


	char 	*fields;
	int 	fieldlen;
	int	type;

	char	*replace;
	int	replacelen;
	int	replacetype;

#define SIP_DIV_REPLACE_TYPE_STRING	0
#define SIP_DIV_REPLACE_TYPE_INT	1

#define SIP_DIV_STATUS		0		/* status line */
#define SIP_DIV_FROM		1		/* From: */
#define SIP_DIV_TO		2		/* To: */
#define SIP_DIV_VIA		3		/* Via: */
#define SIP_DIV_CALLERID	4		/* Caller-ID: */
#define SIP_DIV_USERAGENT	5		/* User-Agent: */
#define SIP_DIV_CONTENTTYPE	6		/* Content-Type: */
#define SIP_DIV_ACCEPTCONTACT	7		/* Accept-Contact: */
#define SIP_DIV_MAXFORWARDS	8		/* Max-Forwards: */
#define SIP_DIV_CONTACT		9		/* Contact: */
#define SIP_DIV_CSEQ		10		/* CSeq: */
#define SIP_DIV_SUPPORTED	11		/* Supported: */
#define SIP_DIV_ALLOW		12		/* Allow: */
#define SIP_DIV_ALLOWEVENTS	13		/* Allow-Events: */
#define SIP_DIV_EVENT		14
#define	SIP_DIV_REFERTO		15
#define SIP_DIV_REFERREDBY	16
#define SIP_DIV_REJECTCONTACT	17
#define	SIP_DIV_SUBJECT		18
#define	SIP_DIV_ALERTINFO	19
#define	SIP_DIV_CALLINFO	20
#define	SIP_DIV_DATE		21
#define	SIP_DIV_ERRORINFO	22
#define	SIP_DIV_MAXBREADTH	23
#define	SIP_DIV_ORGANIZATION	24
#define	SIP_DIV_PRIORITY	25
#define	SIP_DIV_PROXYAUTHEN	26
#define	SIP_DIV_PROXYAUTHOR	27
#define	SIP_DIV_PROXYREQ	28
#define	SIP_DIV_RECORDROUTE	29
#define SIP_DIV_EXPIRES		30
#define	SIP_DIV_REQUIRE		31
#define	SIP_DIV_ROUTE		32
#define	SIP_DIV_WWWAUTH		33
#define	SIP_DIV_SECURECLIENT	34
#define	SIP_DIV_SECUREVERIFY	35
#define	SIP_DIV_SECURESERVER	36
#define	SIP_DIV_ANSWERMODE	37
#define	SIP_DIV_PRIVANSWERMODE	38
#define	SIP_DIV_HISTORYINFO	39
#define	SIP_DIV_PATH		40
#define	SIP_DIV_IDENTITY	41
#define	SIP_DIV_IDENTITYINFO	42
#define	SIP_DIV_PASSERTEDID	43
#define	SIP_DIV_REASON		44
#define	SIP_DIV_RESOURCEPRIO	45
#define	SIP_DIV_AUTHINFO	46
#define SIP_DIV_XAUSERAGENT	47
#define SIP_DIV_XACONTACT	48
#define SIP_DIV_CONTENTENC	49
#define SIP_DIV_CONTENTLEN	50
#define SIP_DIV_ACCEPT		51
#define SIP_DIV_ACCEPTENC	52
#define SIP_DIV_ACCEPTLANG	53
#define SIP_DIV_AUTHORIZATION	54
#define SIP_DIV_MAX		55

	char 	*body;
	int	bodylen;


	SLIST_ENTRY(sipdata) entries;
} *n1, *n2, *np;


struct tok {
	int type;
	char *token;
	char *shortform;
} tokens[] = {
	{ SIP_DIV_STATUS, "YCVFDSAFEWQFQF", NULL	},
	{ SIP_DIV_VIA, "Via:"	, "v:"			},
	{ SIP_DIV_ROUTE		, "Route:", NULL },
	{ SIP_DIV_FROM, "From:"	, "f:"			},
	{ SIP_DIV_TO, "To:", "t:"				},
	{ SIP_DIV_CALLERID, "Call-ID:", "i:"		},
	{ SIP_DIV_CSEQ, "CSeq:", NULL				},
	{ SIP_DIV_CONTACT, "Contact:", "m:"		},
	{ SIP_DIV_AUTHORIZATION, "Authorization:", NULL	},
	{ SIP_DIV_MAXFORWARDS, "Max-Forwards:", NULL	},
	{ SIP_DIV_EXPIRES , "Expires:" , NULL},
	{ SIP_DIV_USERAGENT, "User-Agent:", NULL	},
	{ SIP_DIV_SUPPORTED, "Supported:", NULL		},
	{ SIP_DIV_ALLOWEVENTS, "Allow-Events:"	, "u:"	},
	{ SIP_DIV_ALLOW, "Allow:", NULL			},
	{ 	SIP_DIV_ACCEPT		, "Accept:", NULL },
	{	SIP_DIV_ACCEPTENC	, "Accept-Encoding:", NULL },
	{ SIP_DIV_ACCEPTCONTACT, "Accept-Contact:", "a:"	},
	{ SIP_DIV_EVENT, "Event:" , "o:"		},
	{ SIP_DIV_REFERTO, "Refer-To:"		, "r:"	},
	{ SIP_DIV_REFERREDBY, "Referred-By:", "b:"	},
	{ SIP_DIV_REJECTCONTACT, "Reject-Contact:", "j:" },
	{ SIP_DIV_SUBJECT, "Subject:", "s:"		},
	{	SIP_DIV_ALERTINFO	, "Alert-Info:", NULL },
	{	SIP_DIV_CALLINFO	, "Call-Info:", NULL	},
	{	SIP_DIV_DATE		, "Date:", NULL	},
	{	SIP_DIV_ERRORINFO	, "Error-Info:", NULL	},
	{	SIP_DIV_MAXBREADTH	, "Max-Breadth:", NULL },
	{	SIP_DIV_ORGANIZATION	, "Organization:", NULL },
	{	SIP_DIV_PRIORITY	, "Priority:", NULL	},
	{	SIP_DIV_PROXYAUTHEN	, "Proxy-Authenticate:", NULL },
	{	SIP_DIV_PROXYAUTHOR	, "Proxy-Authorization:", NULL },
	{	SIP_DIV_PROXYREQ	, "Proxy-Require:", NULL },
	{	SIP_DIV_RECORDROUTE	, "Record-Route:", NULL },
	{	SIP_DIV_REASON		, "Reason:", NULL },
	{	SIP_DIV_REQUIRE		, "Require:", NULL },
	{	SIP_DIV_WWWAUTH		, "WWW-Authenticate:", NULL },
	{	SIP_DIV_SECURECLIENT	, "Security-Client:", NULL },
	{	SIP_DIV_SECUREVERIFY	, "Security-Verify:" , NULL },
	{	SIP_DIV_SECURESERVER	, "Secure-Server:" , NULL },
	{	SIP_DIV_ANSWERMODE	, "Answer-Mode:" , NULL },
	{	SIP_DIV_PRIVANSWERMODE	, "Priv-Answer-Mode:" , NULL },
	{	SIP_DIV_HISTORYINFO	, "History-Info:" , NULL },
	{	SIP_DIV_PATH		, "Path:" , NULL },
	{	SIP_DIV_IDENTITY	, "Identity:" , NULL },
	{	SIP_DIV_IDENTITYINFO	, "Identity-Info:" , NULL },
	{	SIP_DIV_PASSERTEDID	, "P-Asserted-Identity:" , NULL },
	{	SIP_DIV_RESOURCEPRIO	, "Resource-Priority:" , NULL },
	{	SIP_DIV_AUTHINFO	, "Auth-Info:" , NULL },
	{ 	SIP_DIV_XAUSERAGENT	, "X-A-User-Agent:" , NULL },
	{  	SIP_DIV_XACONTACT	, "X-A-Contact:" , NULL },
	{ 	SIP_DIV_ACCEPTLANG	, "Accept-Language:" , NULL },
	{ 	SIP_DIV_CONTENTENC	, "Content-Encoding:", "e:" },
	{ SIP_DIV_CONTENTTYPE, "Content-Type:"	, "c:" },
	{ 	SIP_DIV_CONTENTLEN	, "Content-Length:", "l:" },
	{ SIP_DIV_MAX, NULL, NULL }
};


int parse_payload(char *, int);
int new_payload(char *, int);
void destroy_payload(void);
void add_header(char *, char *);

int sip_compact = 0;
char *useragent = "User-Agent: AVM\r\n";

int
main(int argc, char *argv[])
{
	int savelen, len;
	int ds, sslen = sizeof(struct sockaddr_in);
	int ch, debug = 0;
	int iphl = sizeof(struct ip);
	int udphl = sizeof(struct udphdr);

	char buf[65535];
	char abuf[INET6_ADDRSTRLEN];
	char *payload;

	struct ip *ip;
	struct udphdr *udp;
	struct sockaddr_in sin;

	while ((ch = getopt(argc, argv, "cd")) != -1) {
		switch (ch) {
		case 'c':
			sip_compact = 1;
			break;
		case 'd':
			debug = 1;
			break;
		default:
			fprintf(stderr, "usage: sipdiv [-c][-d]\n");
			exit (1);
		}
	}

	SLIST_INIT(&head);
		
	openlog("sipdiv", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	syslog(LOG_INFO, "sipdiv starting up");
	
	ds = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
	if (ds < 0) {
		perror("socket");
		exit(1);
	}

	memset(&sin, 0, sizeof(sin));	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(22222);

	if (bind(ds, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		exit(1);
	}

	if (! debug)
		daemon(0,0);

	if (pledge("stdio inet unveil", NULL) == -1) {
		perror("pledge");
		exit(1);
	}

	if (unveil(NULL, NULL) == -1) {
		perror("unveil");
		exit(1);
	}

	if (pledge("stdio inet", NULL) == -1) {
		perror("pledge");
		exit(1);
	}


	for (;;) {
		len = recvfrom(ds, buf, sizeof(buf), 0, (struct sockaddr *)&sin, &sslen);		
	
		if (len < 0) {
			perror("read");
			continue;
		}	

		if (len < sizeof(struct ip))
			continue;

		ip = (struct ip *)&buf[0];
		
		if (ip->ip_p != IPPROTO_UDP)
			goto skip;

		iphl = (ip->ip_hl * 4);

		
		if (len < (iphl + udphl))
			continue;

		savelen = len;

		udp = (struct udphdr *)&buf[iphl];
	
		payload = &buf[iphl + udphl];


		printf("--------------------------------------------------------------------\n");
		inet_ntop(AF_INET, (char *)&ip->ip_src, (char *)&abuf, sizeof(abuf));
		printf("SOURCE: %s\n", abuf);
		inet_ntop(AF_INET, (char *)&ip->ip_dst, (char *)&abuf, sizeof(abuf));
		printf("DEST: %s\n", abuf);	
		printf("HOPS: %d\n", ip->ip_ttl);

		printf("SRCPORT: %d\n", ntohs(udp->uh_sport));
		printf("DSTPORT: %d\n", ntohs(udp->uh_dport));


		printf("LEN: %d\n", len);

		if (parse_payload(payload, len - (iphl + udphl)) < 0) {
			fprintf(stderr, "parse_payload failure, skip\n");
			goto skip;
		}

		len = new_payload(payload, sizeof(buf) - iphl - udphl);
		if (len < 0) {
			len = savelen;
			goto skip;
		}

		len += (udphl + iphl);
		
		destroy_payload();


#if 0
		while (len > 1400) {
			backup = memrchr(buf, '\n', len);
			if (backup == NULL) {
				printf("ruh roh\n");
				len = savelen;

				goto skip;
			}
				
			len = backup - &buf[0];
			len--;

			if (len <= 1400) {
				buf[len++] = '\r';
				buf[len++] = '\n';
				buf[len++] = '\r';
				buf[len++] = '\n';

				break;
			}
		}
#endif
		if (len > 1420)
			fprintf(stderr, "ruh roh, len > 1420\n");

		printf("NEWLEN: %d\n", len);
		
		NTOHS(ip->ip_len);
		ip->ip_len -= (savelen - len);
		HTONS(ip->ip_len);

		NTOHS(udp->uh_ulen);
		udp->uh_ulen -= (savelen - len);
		HTONS(udp->uh_ulen);

		printf("--------------------------------------------------------------------\n");
skip:
		if (sendto(ds, buf, len, 0, (struct sockaddr*)&sin, sslen) < 0) {
			perror("write");
		}
	} /* for(;;) */
}





int
parse_payload(char *payload, int len)
{
	char *nl;

	int newlen, i;
	int header = 0;
	int seencl = 0;

	do {
		nl = memchr(payload, '\n', len);
		if (nl == NULL) {
			if (len <= 4) {
				n1 = calloc(sizeof(struct sipdata), 1);
				if (n1 == NULL) {
					perror("calloc");
					return (-1);
				}

				n1->fields = malloc(len + 1);
				if (n1->fields == NULL) {
					perror("malloc");
					return (-1);
				}
				memcpy(n1->fields, payload, len);
				n1->fields[len] = '\0';
				n1->fieldlen = len;
				n1->flags |= SIP_DIV_FLAG_BODY;
				n1->type = 0;
				SLIST_INSERT_HEAD(&head, n1, entries);

				return len;
			} else
				return (-1);
		}

		newlen = (nl - payload);
		if (newlen < len) {
			nl++;
			newlen++;
		}

		n1 = calloc(sizeof(struct sipdata), 1);
		if (n1 == NULL) {
			perror("calloc");
			return (-1);
		}

		if (seencl == 1) {
			n1->fields = malloc(len + 1);
			if (n1->fields == NULL) {
				perror("malloc");
				return (-1);
			}
			memcpy(n1->fields, payload, len);
			n1->fields[len] = '\0';
			n1->fieldlen = len;
			n1->flags |= SIP_DIV_FLAG_BODY;
			n1->type = 0;
			SLIST_INSERT_HEAD(&head, n1, entries);

			break;
		}

	
		if (header == 0) {

			n1->fields = malloc(newlen);
			if (n1->fields == NULL) {
				perror("malloc");
				return (-1);
			}

			memcpy(n1->fields, payload, newlen);
			n1->fieldlen = newlen;
			n1->flags |= SIP_DIV_FLAG_HEADER;
			n1->type = SIP_DIV_STATUS;
			SLIST_INSERT_HEAD(&head, n1, entries);
			header++;

		} else {
			for (i=0; tokens[i].token != NULL; i++) {
				if (memcmp(payload, tokens[i].token, strlen(tokens[i].token)) == 0) {
					if (tokens[i].type == SIP_DIV_CONTENTLEN)
						seencl = 1;

					n1->fields = malloc(newlen);
					if (n1->fields == NULL) {
						perror("malloc");
						return (-1);
					}
					memcpy(n1->fields, payload, newlen);
					n1->fieldlen = newlen;
					n1->flags |= SIP_DIV_FLAG_HEADER;
					n1->type = tokens[i].type;

					if (n1->type == SIP_DIV_USERAGENT) {
						n1->replace = strdup(useragent);
						n1->replacelen = strlen(n1->replace);
					} else if (n1->type == SIP_DIV_EXPIRES) {
						n1->replace = strdup("Expires: 300\r\n");
						n1->replacelen = strlen(n1->replace);
					}

					if (sip_compact == 1 && tokens[i].shortform != NULL) {
						int tokenlen = (n1->fieldlen - strlen(tokens[i].token)) + strlen(tokens[i].shortform);

						n1->replace = malloc(tokenlen);
						if (n1->replace == NULL) {
							perror("malloc");
							return (-1);	
						}

						n1->replacelen = tokenlen;
						memcpy(n1->replace, tokens[i].shortform, strlen(tokens[i].shortform));
						memcpy((&n1->replace[strlen(tokens[i].shortform)]), 
							n1->fields + strlen(tokens[i].token), 
							tokenlen - strlen(tokens[i].shortform));

						n1->flags |= SIP_DIV_FLAG_COMPACT;
					} 
						
					
					SLIST_INSERT_HEAD(&head, n1, entries);

					break;
				} else if ((tokens[i].shortform != NULL) && memcmp(payload, tokens[i].shortform, strlen(tokens[i].shortform)) == 0) {

					n1->fields = malloc(newlen);
					if (n1->fields == NULL) {
						perror("malloc");
						return (-1);
					}
					memcpy(n1->fields, payload, newlen);
					n1->fieldlen = newlen;
					n1->flags |= (SIP_DIV_FLAG_HEADER | SIP_DIV_FLAG_SHORTFORM);
					n1->type = tokens[i].type;
					
					SLIST_INSERT_HEAD(&head, n1, entries);
					break;
				}
			}

#if 1
			if (tokens[i].token == NULL) {
				fprintf(stderr, "no action on unknown header packet offset %u\n", len);
			}
#endif
		}
		
		
		payload = nl;
		len -= newlen;
	} while (len >= 0);

	if (sip_compact)
		add_header("c:", " application/sdp\r\n");

	return (0);
}




void
destroy_payload(void)
{
	while (!SLIST_EMPTY(&head)) {
             n1 = SLIST_FIRST(&head);
	     free(n1->fields);
	     if (n1->replacelen)
		free(n1->replace);
             SLIST_REMOVE_HEAD(&head, entries);
             free(n1);
	}
}

int
new_payload(char *buf, int len)
{
	char tmpbuf[1024];
	int offset = 0;

	if (len < 1400) /* leave it intact */
		return len;

	/* reconstruct header */
	
	for (int i = 0; tokens[i].type != SIP_DIV_MAX; i++) {
		SLIST_FOREACH(np, &head, entries) {
			if (np->flags & SIP_DIV_FLAG_BODY)
				continue;

			if (tokens[i].type == np->type) {
				if (np->flags & SIP_DIV_FLAG_COMPACT) {
					memcpy(&tmpbuf, np->replace, np->replacelen);
					tmpbuf[np->replacelen] = '\0';
					if (tmpbuf[np->replacelen - 2] == '\r')
						tmpbuf[np->replacelen - 2] = '\0';
					printf("%s\n", tmpbuf);
					memcpy(&buf[offset], np->replace, np->replacelen);
					offset += np->replacelen;

				} else {
					if (np->replacelen != 0) {
						memcpy(&tmpbuf, np->replace, np->replacelen);
						tmpbuf[np->replacelen] = '\0';
						if (tmpbuf[np->replacelen - 2] == '\r')
							tmpbuf[np->replacelen - 2] = '\0';
						printf("%s\n", tmpbuf);
						memcpy(&buf[offset], np->replace, np->replacelen);
						offset += np->replacelen;
					} else {
						memcpy(&tmpbuf, np->fields, np->fieldlen);
						tmpbuf[np->fieldlen] = '\0';
						if (tmpbuf[np->fieldlen - 2] == '\r')
							tmpbuf[np->fieldlen - 2] = '\0';
						printf("%s\n", tmpbuf);
						memcpy(&buf[offset], np->fields, np->fieldlen);
						offset += np->fieldlen;
					}
				}
			}
		}
	}

	/* reconstruct body */


	SLIST_FOREACH(np, &head, entries) {
		if (!(np->flags & SIP_DIV_FLAG_BODY))
			continue;

#if 0
		buf[offset++] = '\r';
		buf[offset++] = '\n';
		buf[offset++] = '\r';
		buf[offset++] = '\n';
#endif

		memcpy(&tmpbuf, np->fields, np->fieldlen);
		tmpbuf[np->fieldlen] = '\0';
		if (tmpbuf[np->fieldlen - 2] == '\r')
			tmpbuf[np->fieldlen - 2] = '\0';
		printf("%s\n", tmpbuf);
		memcpy(&buf[offset], np->fields, np->fieldlen);
		offset += np->fieldlen;
		break;
	}

	return (offset);
}


void
add_header(char *header, char *contents)
{
	int len = strlen(header) + strlen(contents);

	n1 = calloc(sizeof(struct sipdata), 1);
	if (n1 == NULL) {
		perror("calloc");
		return;
	}

	n1->fields = malloc(len);
	if (n1->fields == NULL) {
		perror("malloc");
		return;
	}

	n1->fieldlen = len;
	n1->type = SIP_DIV_CONTENTTYPE;

	memcpy(n1->fields, header, strlen(header));
	memcpy((&n1->fields[strlen(header)]), 
		contents, strlen(contents));

	SLIST_INSERT_HEAD(&head, n1, entries);
}
