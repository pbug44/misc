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

#include <netinet/in.h>
#define _KERNEL 1
#include <netinet/ip.h>
#include <netinet/ip6.h>
#undef _KERNEL
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <pwd.h>

#include <ctype.h>

#include "sip.h"

#define PROXIMASIP_USER		"_proximasip"
#define DEFAULT_AVMBOX		"192.168.199.12"
#define MAX_BUFSZ		65535
#define LISTENPORT		12345
#define TIMEOUT			10

#define NO_BIND			0
#define BIND_PORT_EXT		1
#define BIND_PORT_INT		2

#define STATE_INVALID		0
#define STATE_LISTEN		1
#define STATE_INVITE		2

SLIST_HEAD(, sipdata) head;

struct sipdata {
	uint8_t flags;
#define SIP_HEAD_FLAG_HEADER	0x1
#define SIP_HEAD_FLAG_BODY	0x2
#define SIP_HEAD_FLAG_SHORTFORM	0x4
#define SIP_HEAD_FLAG_COMPACT	0x8

	char 	*fields;
	int 	fieldlen;
	int	type;

	char	*replace;
	int	replacelen;
	int	replacetype;

#define SIP_HEAD_REPLACE_TYPE_STRING	0
#define SIP_HEAD_REPLACE_TYPE_INT	1

	char 	*body;
	int	bodylen;


	SLIST_ENTRY(sipdata) entries;
} *n1, *n2, *np;


struct sipconn {
	int af;				/* address family */
	int addrlen;			/* address length */

	int so;				/* socket */
	int state;			/* state of connection */
	int auth;			/* authentication flag */

	time_t connect;			/* first connection time */
	time_t activity;		/* last activity */

	char *hostname;			/* hostname facing the world */
	char *address;			/* remote address */

	struct sockaddr_storage local;	/* local IP */
	struct sockaddr_storage remote; /* remote IP */

	char *inbuf;
	int inbuflen;	
	char *outbuf;
	int outbuflen;
	
	SLIST_ENTRY(sipconn) entries;
};

struct cfg {
	char *myname;
	char *mydomain;

	char *u;		/* username */
	char *p;		/* password */

	char *a;		/* internal hostname usually DEFAULT_AVMBOX */

	struct sockaddr_storage sipbox;			/* AVM box in my case */
	struct sockaddr_storage internal;		/* internal IP */

	int icmp;		/* icmp socket */
	int icmp6;		/* icmp6 socket */
	
	SLIST_HEAD(, sipconn) connection;
};

/* prototypes */
int parse_payload(char *, int);
int new_payload(char *, int);
void destroy_payload(void);
void add_header(char *, char *, int);
int find_header(int);
int listen_proxima(struct cfg *, fd_set *);
void timeout_proxima(struct cfg *);
void proxima_work(struct sipconn *);
void delete_sc(struct cfg *, struct sipconn *);
struct sipconn * proxima(struct cfg *cfg, fd_set *rset);
struct sipconn * add_socket(struct cfg *, uint16_t, char *, uint16_t, int);
void proc_icmp(struct cfg *);
void proc_icmp6(struct cfg *);
void icmp_func(struct cfg *, struct sipconn *, char *, int, int);
void icmp6_func(struct cfg *, struct sipconn *, char *, int, int);


int sip_compact = 0;
char *useragent = "User-Agent: AVM\r\n";

int
main(int argc, char *argv[])
{
	fd_set rset;

	int debug = 0;
	int ch;
	int sel;
	int no_icmp = 0;

	char myname[256];

	struct cfg cfg;
	struct passwd *pw;
	struct sipconn *sc = NULL;

	memset((char *)&cfg, 0, sizeof(cfg));
	
	cfg.a = DEFAULT_AVMBOX;

	while ((ch = getopt(argc, argv, "Ia:du:p:")) != -1) {
		switch (ch) {
		case 'I':
			no_icmp = 1;
			break;
		case 'a':
			cfg.a = strdup(optarg);
			if (cfg.p == NULL) {
				fprintf(stderr, "strdup: %s\n", strerror(errno));
				exit(1);
			}

			break;

		case 'd':
			debug = 1;
			break;

		case 'p':
			if (strncmp(optarg, "$2b$", 4) != 0) {
				fprintf(stderr, "no valid password set\n");
				exit(1);
			}
			cfg.p = strdup(optarg);
			if (cfg.p == NULL) {
				fprintf(stderr, "strdup: %s\n", strerror(errno));
				exit(1);
			}
			break;

		case 'u':
			cfg.u = strdup(optarg);
			if (cfg.p == NULL) {
				fprintf(stderr, "strdup: %s\n", strerror(errno));
				exit(1);
			}
			break;

		
		default:
			fprintf(stderr, "usage: proximasip [-d]\n");
			exit (1);
		}
	}

	if (! no_icmp) {
		/* set up the icmp socket early */
		cfg.icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		cfg.icmp6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMP);

		if ((cfg.icmp == -1) || (cfg.icmp6 == -1)) {
			fprintf(stderr, "can't set up raw socket for icmp\n");
		}

		shutdown(cfg.icmp, SHUT_WR);
		shutdown(cfg.icmp6, SHUT_WR);
	} else {
		cfg.icmp = -1;
		cfg.icmp6 = -1;
	}

	/* get hosts fqdn name */
	if (gethostname(myname, sizeof(myname)) == -1) {
		syslog(LOG_ERR, "no hostname found, setting to localhost");
		snprintf(myname, sizeof(myname), "localhost");
	}

	cfg.myname = strdup(myname);
	if (cfg.myname == NULL) {
		exit(2);
	}

	SLIST_INIT(&cfg.connection);

	/* set up default listening socket */
	if (add_socket(&cfg, LISTENPORT, "delphinusdns.org", 5060, BIND_PORT_EXT) == NULL) {
		exit(1);
	}

	/* set up default internal listening socket */
	if (add_socket(&cfg, 5060, cfg.a, 5060, BIND_PORT_INT) == NULL) {
		exit(1);
	}

	SLIST_INIT(&head);
		


	if (! debug)
		daemon(0,0);

	openlog("proximasip", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_INFO, "proximasip starting up");

	pw = getpwnam(PROXIMASIP_USER);
	if (pw == NULL) {
		perror("getpwnam");
		exit(1);
	}

	if (chroot(pw->pw_dir) == -1) {
		perror("chroot");
		exit(1);
	}
	if (chdir("/") == -1) {
		perror("chdir");
		exit(1);
	}

	if (setgroups(1, &pw->pw_gid) == -1) {
		perror("setgroups");
		exit(1);
	}

	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
		perror("setresgid");
		exit(1);
	}
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
		perror("setresuid");
		exit(1);
	}
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


	/* mainloop */
	for (;;) {
		timeout_proxima(&cfg);

		sel = listen_proxima(&cfg, &rset);
		if (sel < 1)
			continue;

		if ((sc = proxima(&cfg, &rset)) != NULL) {
			proxima_work(sc);
		}
	
		if (FD_ISSET(cfg.icmp, &rset)) {
			proc_icmp(&cfg);
		}
		if (FD_ISSET(cfg.icmp6, &rset)) {
			proc_icmp6(&cfg);
		}
	}

	/* NOTREACHED */
}


int
listen_proxima(struct cfg *cfg, fd_set *rset)
{
	int max = 0;
	struct timeval tv;
	struct sipconn *sc;

	tv.tv_sec = 10;
	tv.tv_usec = 0;

	FD_ZERO(rset);

	SLIST_FOREACH(sc, &cfg->connection, entries) {
		if (sc->state != STATE_LISTEN)
			continue;

		if (sc->so > max) 
			max = sc->so;

		FD_SET(sc->so, rset);
	}

	if (cfg->icmp != -1) {
		if (cfg->icmp > max)
			max = cfg->icmp;
		
		FD_SET(cfg->icmp, rset);
	}
		
	if (cfg->icmp6 != -1) {
		if (cfg->icmp6 > max)
			max = cfg->icmp6;
		
		FD_SET(cfg->icmp6, rset);
	}

	return (select(max + 1, rset, NULL, NULL, &tv));
}

struct sipconn *
proxima(struct cfg *cfg, fd_set *rset)
{
	struct sipconn *sc, *sc0, *sc1, *sc2, *rsc;
	struct sockaddr_storage st;
	struct sockaddr_in *psin;
	struct sockaddr_in6 *psin6;
	socklen_t stlen = sizeof(struct sockaddr_storage);
	static char *buf = NULL;
	char address[INET6_ADDRSTRLEN];
	int len;

	if (buf == NULL) {
		buf = calloc(1, MAX_BUFSZ);
		if (buf == NULL)
			return NULL;
	}

	SLIST_FOREACH_SAFE(sc, &cfg->connection, entries, sc0) {
		if (sc->state != STATE_LISTEN)
			continue;

		if (FD_ISSET(sc->so, rset)) {
			len = recvfrom(sc->so, buf, MAX_BUFSZ, 0, (struct sockaddr *)&st, &stlen);		
			if (len < 0) {
				perror("read");
				return NULL;
			}

			SLIST_FOREACH_SAFE(sc1, &cfg->connection, entries, sc2) {
				if (sc1->state == STATE_LISTEN)
					continue;
				
				if (sc1->af != ((struct sockaddr *)&st)->sa_family)
					continue;

				switch (sc->af) {
				case AF_INET6:
					psin6 = (struct sockaddr_in6 *)&sc1->remote;
					if (memcmp(&psin6->sin6_addr, \
							&((struct sockaddr_in6 *)&st)->sin6_addr, \
							sizeof(struct sockaddr_in6)) == 0)  {
						return (sc1);	
					}	

					break;
				default:
					psin = (struct sockaddr_in *)&sc1->remote;
					if (psin->sin_addr.s_addr == 
							((struct sockaddr_in *)&st)->sin_addr.s_addr) {
						return (sc1);	
					}	
				}
			}
				
			switch (st.ss_family) {
			case AF_INET6:
				psin6 = (struct sockaddr_in6 *)&st;
				inet_ntop(AF_INET6, &psin6->sin6_addr, \
					(char *)&address, sizeof(address));
				rsc = add_socket(cfg, LISTENPORT,address,ntohs(psin6->sin6_port), NO_BIND);
				if (rsc) {
					rsc->address = strdup(address);
					rsc->inbuf = buf;
					rsc->inbuflen = len;
				}

				return (rsc);
				break;
			default:
				psin = (struct sockaddr_in *)&st;
				inet_ntop(AF_INET, &psin->sin_addr.s_addr, \
					(char *)&address, sizeof(address));

				rsc = add_socket(cfg, LISTENPORT, address, ntohs(psin->sin_port), NO_BIND);
				if (rsc) {
					rsc->address = strdup(address);
					rsc->inbuf = buf;
					rsc->inbuflen = len;
				}

				return (rsc);
				break;
			}
		}
	}

	return NULL;
}


/*
 * PROXIMA_WORK - parse what we got and move packets around
 *
 */


void
proxima_work(struct sipconn *sc)
{
	//int len;

	sc->activity = time(NULL);

#if 0
	if (parse_payload(sc->inbuf, sc->inbuflen) < 0) {
		fprintf(stderr, "parse_payload failure, skip\n");
		return;
	}

	len = new_payload(sc->inbuf, sc->inbuflen);
	if (len < 0) {
		return;
	}

	destroy_payload();

	if (sendto(sc->so, buf, len, 0, (struct sockaddr*)&sin, sslen) < 0) {
		perror("write");
	}
#endif
}


/*
 * PARSE_PAYLOAD - from sipdiv.c 
 */

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
				n1->flags |= SIP_HEAD_FLAG_BODY;
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
			n1->flags |= SIP_HEAD_FLAG_BODY;
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
			n1->flags |= SIP_HEAD_FLAG_HEADER;
			n1->type = SIP_HEAD_STATUS;
			SLIST_INSERT_HEAD(&head, n1, entries);
			header++;

		} else {
			for (i=0; tokens[i].token != NULL; i++) {
				if (memcmp(payload, tokens[i].token, strlen(tokens[i].token)) == 0) {
					if (tokens[i].type == SIP_HEAD_CONTENTLEN)
						seencl = 1;

					n1->fields = malloc(newlen);
					if (n1->fields == NULL) {
						perror("malloc");
						return (-1);
					}
					memcpy(n1->fields, payload, newlen);
					n1->fieldlen = newlen;
					n1->flags |= SIP_HEAD_FLAG_HEADER;
					n1->type = tokens[i].type;

					if (n1->type == SIP_HEAD_USERAGENT) {
						n1->replace = strdup(useragent);
						n1->replacelen = strlen(n1->replace);
					} else if (n1->type == SIP_HEAD_EXPIRES) {
						n1->replace = strdup("Expires: 300\r\n");
						n1->replacelen = strlen(n1->replace);
					}

					if ((sip_compact == 1) && 
						(tokens[i].shortform != NULL)) {
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

						n1->flags |= SIP_HEAD_FLAG_COMPACT;
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
					n1->flags |= (SIP_HEAD_FLAG_HEADER | SIP_HEAD_FLAG_SHORTFORM);
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

	if (sip_compact) {
		if (! find_header(SIP_HEAD_CONTENTTYPE)) {
			add_header("Content-Type:", 
				" application/sdp\r\n", SIP_HEAD_CONTENTTYPE);
		}
	}

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
find_header(int type)
{
	SLIST_FOREACH(np, &head, entries) {
		if (np->type == type)
			return 1;
	}
	return 0;
}

int
new_payload(char *buf, int len)
{
	char tmpbuf[1024];
	int offset = 0;

	if (len < 1400) /* leave it intact */
		return len;

	/* reconstruct header */
	
	for (int i = 0; tokens[i].type != SIP_HEAD_MAX; i++) {
		SLIST_FOREACH(np, &head, entries) {
			if (np->flags & SIP_HEAD_FLAG_BODY)
				continue;

			/* strip out known X- Headers, why do we need them? */
			if (sip_compact && ((np->type == SIP_HEAD_XAUSERAGENT) ||
				(np->type == SIP_HEAD_XACONTACT)))
				continue;


			if (tokens[i].type == np->type) {
				if (np->flags & SIP_HEAD_FLAG_COMPACT) {
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
		if (!(np->flags & SIP_HEAD_FLAG_BODY))
			continue;

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
add_header(char *header, char *contents, int type)
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
	n1->type = type; 

	memcpy(n1->fields, header, strlen(header));
	memcpy((&n1->fields[strlen(header)]), 
		contents, strlen(contents));

	SLIST_INSERT_HEAD(&head, n1, entries);
}

struct sipconn *
add_socket(struct cfg *cfg, uint16_t lport, char *rhost, uint16_t rport, int x)
{
	struct addrinfo *res0, *res, hints;
	struct sipconn *sc;
	struct sockaddr_in *psin;
	struct sockaddr_in6 *psin6;
	int so, error;
	socklen_t slen = sizeof(struct sockaddr_storage);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	if (x != NO_BIND) {
		hints.ai_flags = AI_CANONNAME;
	} else {
		hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	}

	error = getaddrinfo(rhost, "5060", &hints, &res0);
	if (error) {
		fprintf(stderr, "getaddrinfo: %s\n", 
			gai_strerror(error));
		return (NULL);
	}

	for (res = res0; res != NULL; res = res->ai_next) {
		so = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (so == -1) {
			perror("socket");
			freeaddrinfo(res0);
			return (NULL);
		}

		if (connect(so, res->ai_addr, res->ai_addrlen) == -1) {
			perror("connect");
			goto out;
		}
		
		sc = calloc(1, sizeof(struct sipconn));
		if (sc == NULL) {
			syslog(LOG_INFO, "calloc: %m");
			goto out;
		}

		slen = res->ai_addrlen;
		if (getsockname(so, (struct sockaddr *)&sc->local, &slen) == -1) {
			perror("getsockname");
			free(sc);
			goto out;
		}
		if (getpeername(so, (struct sockaddr *)&sc->remote, &slen) == -1) {
			perror("getpeername");
			free(sc);
			goto out;
		}
		
		/* if we are internal give it special treatment */
		if (x != NO_BIND) {

			if ((sc->so = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
				perror("socket (2)");
				free(sc);
				goto out;
			}

			sc->af = res->ai_family;
			memcpy((char *)&cfg->sipbox, (char *)&sc->remote, sizeof(struct sockaddr_storage));
			memcpy((char *)&cfg->internal, (char *)&sc->local, sizeof(sc->local));

			switch (sc->af) {
			case AF_INET:
				psin = (struct sockaddr_in *)&sc->remote;
				psin->sin_port = htons(rport);
				psin = (struct sockaddr_in *)&sc->local;
				psin->sin_port = htons(lport);	
				break;
			default:
				psin6 = (struct sockaddr_in6 *)&sc->remote;
				psin6->sin6_port = htons(rport);
				psin6 = (struct sockaddr_in6 *)&sc->local;
				psin6->sin6_port = htons(lport);	
				break;
			}

			if (bind(sc->so, (struct sockaddr *)&sc->local, slen) \
					 == -1) {
				perror("bind");
				free(sc);
				goto out;
			}

			if ((x == BIND_PORT_INT) && (connect(sc->so, \
				(struct sockaddr *)&sc->remote, slen) == -1)) {
				perror("connect");
				free(sc);
				goto out;
			}

			sc->state = STATE_LISTEN;

		} else {
			switch (res->ai_family) {
			case AF_INET:
				psin = (struct sockaddr_in *)&sc->remote;
				psin->sin_port = htons(rport);
				psin = (struct sockaddr_in *)&sc->local;
				psin->sin_port = htons(lport);	
				break;
			default:
				psin6 = (struct sockaddr_in6 *)&sc->remote;
				psin6->sin6_port = htons(rport);
				psin6 = (struct sockaddr_in6 *)&sc->local;
				psin6->sin6_port = htons(lport);	
				break;
			}

			sc->activity = sc->connect = time(NULL);
			sc->state = STATE_INVITE;
		}

		SLIST_INSERT_HEAD(&cfg->connection, sc, entries);
		close(so);
	}

	freeaddrinfo(res0);
	return (sc);

out:
	close(so);
	freeaddrinfo(res0);
	return (NULL);

}

void
timeout_proxima(struct cfg *cfg)
{
	struct sipconn *sc, *sc0;
	time_t now;


	now = time(NULL);

	SLIST_FOREACH_SAFE(sc, &cfg->connection, entries, sc0) {
		if (sc->state == STATE_LISTEN)
			continue;

		if (difftime(now, sc->activity) > TIMEOUT) {
			syslog(LOG_INFO, "timing out connection from %s", 
				sc->address);
			delete_sc(cfg, sc);
		}
	}
}


void
delete_sc(struct cfg *cfg, struct sipconn *sc)
{		
	free(sc->address);

	SLIST_REMOVE(&cfg->connection, sc, sipconn, entries);
	
}

void
proc_icmp(struct cfg *cfg)
{
	static char *buf;
	struct sipconn *sc, *sc0;
	struct sockaddr_in *rsin, sin;
	struct icmp icmp;

	socklen_t slen = sizeof(struct sockaddr_in);
	time_t now;
	int len;

	if (buf == NULL) {
		buf = calloc(1, MAX_BUFSZ);
		if (buf == NULL)
			return;
	}

	len = recvfrom(cfg->icmp, buf, MAX_BUFSZ, 0, (struct sockaddr *)&sin,
		&slen);

	if (len == -1)
		return;

	now = time(NULL);
	SLIST_FOREACH_SAFE(sc, &cfg->connection, entries, sc0) {
		if (sc->state == STATE_LISTEN || sc->af != AF_INET)
			continue;

		/* opportunistic timeout */
		if (difftime(now, sc->activity) > TIMEOUT) {
			syslog(LOG_INFO, "timing out connection from %s", 
				sc->address);
			delete_sc(cfg, sc);
			continue;
		}

		if (len < ICMP_MINLEN)
			continue;

		rsin = (struct sockaddr_in *)&sc->remote;
		if ((rsin->sin_addr.s_addr = sin.sin_addr.s_addr) &&
				(sin.sin_port == rsin->sin_port)) {
			switch(icmp.icmp_type) {
			case ICMP_UNREACH:
			case ICMP_TIMXCEED:
				icmp_func(cfg, sc, buf, len, icmp.icmp_type);
				break;
			default:
				/* no action required */
				break;
			}
		}

		/* else continue foreach loop */
	}
}

void
proc_icmp6(struct cfg *cfg)
{
	static char *buf = NULL;
	struct icmp6_hdr icmp6;
	struct sipconn *sc, *sc0;
	struct sockaddr_in6 *rsin, sin;
	socklen_t slen = sizeof(struct sockaddr_in);
	time_t now;
	int len;

	if (buf == NULL) {
		buf = calloc(1, MAX_BUFSZ);
		if (buf == NULL)
			return;
	}

	len = recvfrom(cfg->icmp6, buf, MAX_BUFSZ, 0, (struct sockaddr *)&sin,
		&slen);

	if (len == -1)
		return;


	now = time(NULL);

	SLIST_FOREACH_SAFE(sc, &cfg->connection, entries, sc0) {
		if (sc->state == STATE_LISTEN || sc->af != AF_INET6)
			continue;

		/* opportunistic timeout */
		if (difftime(now, sc->activity) > TIMEOUT) {
			syslog(LOG_INFO, "timing out connection from %s", 
				sc->address);
			delete_sc(cfg, sc);
			continue;
		}

		if (len < sizeof(struct icmp6_hdr))
			continue;

		rsin = (struct sockaddr_in6 *)&sc->remote;
		if ((memcmp(&rsin->sin6_addr, &sin.sin6_addr, \
				sizeof(sin.sin6_addr)) == 0) &&
				(sin.sin6_port == rsin->sin6_port)) {
			switch(icmp6.icmp6_type) {
			case ICMP6_DST_UNREACH:
			case ICMP6_TIME_EXCEEDED:
				icmp6_func(cfg, sc, buf, len, icmp6.icmp6_type);
				break;
			default:
				/* no action required */
				break;
			}
		}
	}
}

void
icmp_func(struct cfg *cfg, struct sipconn *sc, char *buf, int len, int type)
{
	struct sockaddr_in *lsin, *rsin;
	struct ip ip;
	struct icmp icmph;
	struct udphdr udp;
	int iplen;

	if (len < ICMP_ADVLENMIN)
		return;

	memcpy((void *)&icmph, (char *)buf, ICMP_MINLEN);
	memcpy(&ip, &buf[ICMP_MINLEN], sizeof(struct ip));

	iplen = (4 * ip.ip_hl) + ICMP_MINLEN;

	if (len < (iplen + sizeof(struct udphdr)))
		return;

	memcpy(&udp, &buf[iplen], sizeof(struct udphdr));

	lsin = (struct sockaddr_in *)&sc->local;
	rsin = (struct sockaddr_in *)&sc->remote;
	if ((lsin->sin_addr.s_addr != ip.ip_src.s_addr) &&
		(lsin->sin_port != udp.uh_sport) &&
		(rsin->sin_addr.s_addr != ip.ip_dst.s_addr) &&
		(rsin->sin_port != udp.uh_dport)) {
		return;
	}

	/* XXX I'd like to dig deeper but we'll have to see */
	/* all checks are done, proceed to act on them */

	syslog(LOG_INFO, "dropping state from %s port %u due to ICMP type %s"
				" code %u", sc->address, ntohs(rsin->sin_port),  \
				(icmph.icmp_type == ICMP_UNREACH) ? "unreach" : \
				"timex", icmph.icmp_code);

	delete_sc(cfg, sc);
}

void
icmp6_func(struct cfg *cfg, struct sipconn *sc, char *buf, int len, int type)
{
	struct sockaddr_in6 *lsin, *rsin;
	struct ip6_hdr ip6;
	struct icmp6_hdr icmp6;
	struct udphdr udp;
	int iplen;

	if (len < sizeof(struct icmp6_hdr))
		return;

	memcpy((char *)&icmp6, buf, sizeof(struct icmp6_hdr));
	memcpy((char *)&ip6, &buf[sizeof(struct ip6_hdr)], sizeof(struct ip6_hdr));
	if (ip6.ip6_nxt != IPPROTO_UDP)
		return;

	iplen = (sizeof(struct icmp6_hdr)) + (sizeof(struct ip6_hdr));

	if (len < (iplen + sizeof(struct udphdr)))
		return;

	memcpy((char *)&udp, &buf[iplen], sizeof(struct udphdr));

	lsin = (struct sockaddr_in6 *)&sc->local;
	rsin = (struct sockaddr_in6 *)&sc->remote;
	if (memcmp(&lsin->sin6_addr, &ip6.ip6_src, sizeof(ip6.ip6_src)) &&
		(lsin->sin6_port != udp.uh_sport) &&
		memcmp(&rsin->sin6_addr, &ip6.ip6_dst, sizeof(ip6.ip6_dst)) &&
		(rsin->sin6_port != udp.uh_dport)) {
		return;
	}

	/* XXX I'd like to dig deeper but we'll have to see */
	/* all checks are done, proceed to act on them */

	syslog(LOG_INFO, "IP6 dropping state from %s port %u due to ICMP type %s"
				" code %u", sc->address, ntohs(rsin->sin6_port),  \
				(icmp6.icmp6_type == ICMP6_DST_UNREACH) ? "unreach" : \
				"timex", icmp6.icmp6_code);

	delete_sc(cfg, sc);
}
