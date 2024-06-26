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

#include <sys/param.h>
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

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include "sip.h"
#include "rfc3261.h"

#define PROXIMASIP_USER		"_proximasip"
#define DEFAULT_AVMBOX		"192.168.199.12"
#define DEFAULT_USER		"anonymous"
#define MAX_BUFSZ		65535
#define LISTENPORT		12345
#define TIMEOUT			10

#define NO_BIND			0
#define BIND_PORT_EXT		1
#define BIND_PORT_INT		2

#define STATE_INVALID		0
#define STATE_LISTEN		1
#define STATE_TRYING		2
#define STATE_PROCEEDING	3
#define STATE_COMPLETED		4
#define STATE_TERMINATED	5

#define BRANCH_MAGIC		"z9hG4bK"

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
};


struct parsed {
	uint64_t id;
	int direction;
#define SIP_INBOUND	0
#define SIP_OUTBOUND	1

	SLIST_HEAD(,sipdata) data;
	SLIST_ENTRY(parsed) entries;
};


struct sipconn {
	char branchid[32];		/* Via branchid */

	int af;				/* address family */
	int addrlen;			/* address length */

	uint64_t flags;			/* some flags */

#define INVITE_RETRANSMIT		0x2
#define INVITE_TIMEOUT			0x4
#define PROXY_INVITE_TIMEOUT		0x8
#define RESPONSE_RETRANSMIT0		0x10
#define NONINVITE_RETRANSMIT		0x20
#define NONINVITE_TRANSACTION		0x40
#define INVITE_RESPONSE_RETRANSMIT	0x80
#define ACK_RECEIPT_TIMEOUT		0x100
#define ACK_RETRANSMIT			0x200
#define NONINVITE_REQUEST		0x400
#define RESPONSE_RETRANSMIT1		0x800

	int internal;			/* inward facing proxy conn */
	int so;				/* socket */
	int state;			/* state of connection */
	int auth;			/* authentication flag */
	int method;			/* last method received */

	time_t connect;			/* first connection time */
	time_t activity;		/* last activity */
#define TIMER_MAX	11
	time_t timers[TIMER_MAX];	/* several timers */
#define TIMER_A		0		/* INVITE request re-transmit for UDP */
#define TIMER_B		1		/* INVITE timeout */
#define TIMER_C		2		/* Proxy INVITE timeout */
#define TIMER_D		3		/* wait time (response retransmits) */
#define TIMER_E		4		/* non-INVITE retransmit interval UDP */
#define TIMER_F		5		/* non-INVITE transaction timeout */
#define TIMER_G		6		/* INVITE response retransmit intrval */
#define TIMER_H		7		/* wait time for ACK Receipt */
#define TIMER_I		8		/* wait time for ACK retransmits */
#define TIMER_J		9		/* wait time for on-INVITE rtransmits */
#define TIMER_K		10		/* wait time for response retransmits */


/* Table 4 of RFC 3621 */

#define SIP_T1		1		/* RTT estimate 1 second (granularity)*/
#define SIP_T2		4		/* retransmit non-invite requests */
#define SIP_T3		SIP_T2		/* ..and INVITE responses */
#define SIP_T4		5		/* max duration for a message */

#define SET_TIMER_A(_sc, _t)	((_sc)->timers[TIMER_A] = (_t + SIP_T1))
#define SET_TIMER_B(_sc, _t) 	((_sc)->timers[TIMER_B] = (_t + (64 * SIP_T1)))
#define SET_TIMER_C(_sc, _t)	((_sc)->timers[TIMER_C] = (_t + (3 * 60)))
#define SET_TIMER_D(_sc, _t)	((_sc)->timers[TIMER_D] = (_t + (48)))
#define SET_TIMER_E(_sc, _t)	((_sc)->timers[TIMER_E] = (_t + SIP_T1))
#define SET_TIMER_F(_sc, _t)	((_sc)->timers[TIMER_F] = (_t + (64 * SIP_T1)))
#define SET_TIMER_G(_sc, _t)	((_sc)->timers[TIMER_G] = (_t + SIP_T1))
#define SET_TIMER_H(_sc, _t)	((_sc)->timers[TIMER_H] = (_t + (64 * SIP_T1)))
#define SET_TIMER_I(_sc, _t)	((_sc)->timers[TIMER_I] = (_t + SIP_T4))
#define SET_TIMER_J(_sc, _t)	(_sc)->timers[TIMER_J] = (_t + (64 * SIP_T1))
#define SET_TIMER_K(_sc, _t)	((_sc)->timers[TIMER_K] = (_t + SIP_T4))

#define SET_ALL_TIMERS(_sc, now) 	do { \
		SET_TIMER_A(_sc, now); \
		SET_TIMER_B(_sc, now); \
		SET_TIMER_C(_sc, now); \
		SET_TIMER_D(_sc, now); \
		SET_TIMER_E(_sc, now); \
		SET_TIMER_F(_sc, now); \
		SET_TIMER_G(_sc, now); \
		SET_TIMER_H(_sc, now); \
		SET_TIMER_I(_sc, now); \
		SET_TIMER_J(_sc, now); \
		SET_TIMER_K(_sc, now); \
} while (0)


	char *laddress;			/* local address */
	char *address;			/* remote address */

	struct sockaddr_storage local;	/* local IP */
	struct sockaddr_storage remote; /* remote IP */

	char *inbuf;
	int inbuflen;	
	char *outbuf;
	int outbuflen;

	/* DIGEST functions as per RFC 7235 (obsoletes RFC 2617) */

	/* also see RFC 7616 for SHA-256 */

	uint8_t	alg;			/* the algorithm used */
	int qop;

#define ALG_MD5		0		/* "MD5" */
#define ALG_SHA2	1		/* "SHA-256" */
#define ALG_SHA5	2		/* "SHA-512-256" */

	char *ha1;			/* username|":"|realm|":"|password */
	size_t ha1_len;			/* length of ha1 hash */

	char *nonce;			/* nonce */
	size_t nonce_len;

	uint64_t nc;			/* starting at 1 */
	char *cnonce;			/* client nonce */
	size_t cnonce_len;		/* client nonce len */	

	char *opaque;			/* some value */
	size_t opaque_len;

#define BUF_NONCE	0
#define BUF_OPAQUE	1

	char *ha2;			/* ha1|":"|nonce|":"|cnonce all hex */
	size_t ha2_len;			/* length of ha2 hash */

	SLIST_HEAD(,parsed) packets;
	SLIST_ENTRY(sipconn) entries;

	struct sipconn *parent;		/* parent request */
};

struct cfg {
	char *myname;
	char *mydomain;

	char *u;		/* username */
	u_char *p;		/* password */

	struct {
		char *ha1;
		size_t ha1_len;
	} ha[2];

	char *a;		/* internal hostname usually DEFAULT_AVMBOX */

	struct sockaddr_storage sipbox;			/* AVM box in my case */
	struct sockaddr_storage internal;		/* internal IP */

	int icmp;		/* icmp socket */
	int icmp6;		/* icmp6 socket */
	
	SLIST_HEAD(, sipconn) connection;	/* really also a transaction */
};

/* prototypes */
int parse_payload(struct sipconn *);
int comp_payload(struct parsed *, char *, int);
int new_payload(struct parsed *, char *, int);
void destroy_payload(struct parsed *);
void add_header(struct parsed *, char *, char *, int);
int copy_header(struct parsed *, int, struct parsed *, int);
struct sipdata * find_header(struct parsed *, int);
int listen_proxima(struct cfg *, fd_set *);
void timeout_proxima(struct cfg *);
int proxima_work(struct cfg *, struct sipconn *);
void delete_sc(struct cfg *, struct sipconn *);
struct sipconn * copy_sc(struct cfg *, struct sipconn *);
struct sipconn * proxima(struct cfg *, fd_set *);
struct sipconn * add_socket(struct cfg *, uint16_t, char *, uint16_t, int);
void proc_icmp(struct cfg *);
void proc_icmp6(struct cfg *);
void icmp_func(struct cfg *, struct sipconn *, char *, int, int);
void icmp6_func(struct cfg *, struct sipconn *, char *, int, int);
int check_rfc3261(struct sipconn *, int *);
int reply_trying(struct cfg *, struct sipconn *);
int reply_4xx(struct sipconn *, int);
int reply_internal_error(struct cfg *, struct sipconn *);
struct sipconn * try_proxy(struct cfg *, struct sipconn *);
struct sipconn * copy_sc(struct cfg *, struct sipconn *);
u_char * calculate_ha1(char *, char *, char *, int, size_t *);
u_char * calculate_ha2(char *, int, char *, size_t *);
int reply_proxy_authenticate(struct cfg *, struct sipconn *);
struct sipconn * authenticate(struct cfg *, struct sipconn *);
char * statuscode_s(int);
int typeheader(int, char *, int);
void my_syslog(int, char *, ...);
int get_method(struct parsed *);

extern int mybase64_encode(u_char const *, size_t, char *, size_t);
extern int mybase64_decode(char const *, u_char *, size_t);



int sip_compact = 1;		/* compress all sip packets */
char *useragent = "User-Agent: AVM\r\n";
int debug = 0;

int
main(int argc, char *argv[])
{
	fd_set rset;

	int ch, alg;
	int sel;
	int no_icmp = 0;

	char *buf = NULL;
	char *p = NULL;
	char myname[256];

	struct cfg cfg;
	struct passwd *pw;
	struct sipconn *sc = NULL;

	memset((char *)&cfg, 0, sizeof(cfg));
	
	cfg.a = strdup(DEFAULT_AVMBOX);
	cfg.u = strdup(DEFAULT_USER);
	
	if ((cfg.a == NULL) || (cfg.u == NULL)) {
		perror("strdup");
		exit(1);
	}

#ifdef DEFAULT_PASS
	cfg.p = DEFAULT_PASS;
#else
	buf = calloc_conceal(1, 64);
	if (buf == NULL) {
		perror("calloc");
		exit(1);
	}
	arc4random_buf(myname, sizeof(myname));
	mybase64_encode(myname, 16, buf, 64);
	cfg.p = buf;
	explicit_bzero((char *)&myname, sizeof(myname));
#endif

	while ((ch = getopt(argc, argv, "Ia:du:p:")) != -1) {
		switch (ch) {
		case 'I':
			no_icmp = 1;
			break;
		case 'a':
			cfg.a = strdup(optarg);
			if (cfg.a == NULL) {
				fprintf(stderr, "strdup: %s\n", strerror(errno));
				exit(1);
			}

			break;

		case 'd':
			debug = 1;
			break;

		case 'p':
			cfg.p = strdup(optarg);
			if (cfg.p == NULL) {
				fprintf(stderr, "password\n");
				exit(1);
			}
			break;
		case 'u':
			cfg.u = strdup(optarg);
			if (cfg.u == NULL) {
				fprintf(stderr, "strdup: %s\n", strerror(errno));
				exit(1);
			}
			break;
		default:
			fprintf(stderr, "usage: proximasip [-d]\n");
			exit (1);
		}
	}

	/* get hosts fqdn name */
	if (gethostname((char *)&myname, sizeof(myname)) == -1) {
		fprintf(stderr, "no hostname found, setting to localhost\n");
		snprintf(myname, sizeof(myname), "localhost");
	}

	cfg.myname = strdup(myname);
	if (cfg.myname == NULL) {
		perror("strdup");
		exit(1);
	}

	if ((p = strchr(myname, '.')) == NULL) {
		cfg.mydomain = myname;
	} else {
		p++;
		if (*p != '\0')
			cfg.mydomain = p;
		else
			cfg.mydomain = myname;
	}

	for (alg = ALG_MD5; alg <= ALG_SHA2; alg++) {
		cfg.ha[alg].ha1 = calculate_ha1((char *)&cfg.u, (char *)&cfg.p,\
			(char *)&cfg.mydomain, alg, &cfg.ha[alg].ha1_len);

		if (cfg.ha[alg].ha1 == NULL) {
			perror("ha1 failure");
			exit(1);
		}
	}

	/* clean ourselves up */
	explicit_bzero(&cfg.p, strlen(cfg.p));
	explicit_bzero(&cfg.u, strlen(cfg.u));

	/* cloak the arguments */
	setproctitle("cloaked");

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


	SLIST_INIT(&cfg.connection);

	/* leave delphinusdns.org here for now, finds the gateway interface */
	/* XXX yes I know it phones home */
	if (add_socket(&cfg, LISTENPORT, "delphinusdns.org", 5060, BIND_PORT_EXT) == NULL) {
		exit(1);
	}

	/* set up default internal listening socket */
	if (add_socket(&cfg, 5060, cfg.a, 5060, BIND_PORT_INT) == NULL) {
		exit(1);
	}

	if (! debug) {
		daemon(0,0);
	}

	openlog("proximasip", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	my_syslog(LOG_INFO, "proximasip starting up");

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
			if (proxima_work(&cfg, sc) == -1) {
				continue;
			}
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

	tv.tv_sec = SIP_T1;
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
	static char *inbuf = NULL;
	static char *outbuf = NULL;
	char address[INET6_ADDRSTRLEN];
	int len;

	if (inbuf == NULL) {
		if (debug)
			inbuf = calloc(1, MAX_BUFSZ);
		else
			inbuf = calloc_conceal(1, MAX_BUFSZ);

		if (inbuf == NULL)
			return NULL;
	}
	if (outbuf == NULL) {
		if (debug)
			outbuf = calloc(1, MAX_BUFSZ);
		else
			outbuf = calloc_conceal(1, MAX_BUFSZ);

		if (outbuf == NULL)
			return NULL;
	}

	SLIST_FOREACH_SAFE(sc, &cfg->connection, entries, sc0) {
		if (sc->state != STATE_LISTEN)
			continue;

		if (FD_ISSET(sc->so, rset)) {
			len = recvfrom(sc->so, inbuf, MAX_BUFSZ, 0, (struct sockaddr *)&st, &stlen);		
			if (len < 0) {
				perror("read");
				return NULL;
			}

			SLIST_FOREACH_SAFE(sc1, &cfg->connection, entries, sc2) {
				if (sc1->state == STATE_LISTEN)
					continue;
				
				if (sc1->af != ((struct sockaddr *)&st)->sa_family)
					continue;
				
				/* some initializing on the LISTEN states */

				sc1->inbuf = inbuf;
				sc1->outbuf = outbuf;
				sc1->inbuflen = MAX_BUFSZ;
				sc1->outbuflen = MAX_BUFSZ;

				switch (sc->af) {
				case AF_INET6:
					psin6 = (struct sockaddr_in6 *)&sc1->remote;
					if ((memcmp(&psin6->sin6_addr,
							&((struct sockaddr_in6 *)&st)->sin6_addr,
							sizeof(struct sockaddr_in6)) == 0)  && 
						(psin6->sin6_port ==
							((struct sockaddr_in6 *)&st)->sin6_port))
{
						return (sc1);	
					}	

					break;
				default:
					psin = (struct sockaddr_in *)&sc1->remote;
					if ((psin->sin_addr.s_addr == 
							((struct sockaddr_in *)&st)->sin_addr.s_addr) &&
						(psin->sin_port == 
							((struct sockaddr_in *)&st)->sin_port)) {
						return (sc1);	
					}	
				}
			}

			/* make a new state here */
				
			switch (st.ss_family) {
			case AF_INET6:
				psin6 = (struct sockaddr_in6 *)&st;
				inet_ntop(AF_INET6, &psin6->sin6_addr, \
					(char *)&address, sizeof(address));
				rsc = add_socket(cfg, LISTENPORT,address,ntohs(psin6->sin6_port), NO_BIND);
				if (rsc) {
					rsc->parent = sc;
					rsc->address = strdup(address);
					if (rsc->address == NULL) {
						my_syslog(LOG_INFO, "strdup: %m");
						return (NULL);
					}
					rsc->laddress = sc->laddress;	/*dont need to ever clean*/
					rsc->inbuf = inbuf;
					rsc->inbuflen = len;
	
					rsc->outbuflen = MAX_BUFSZ;
					rsc->outbuf = outbuf;
				}

				return (rsc);
				break;
			default:
				psin = (struct sockaddr_in *)&st;
				inet_ntop(AF_INET, &psin->sin_addr.s_addr, \
					(char *)&address, sizeof(address));

				rsc = add_socket(cfg, LISTENPORT, address, ntohs(psin->sin_port), NO_BIND);
				if (rsc) {
					rsc->parent = sc;
					rsc->address = strdup(address);
					if (rsc->address == NULL) {
						my_syslog(LOG_INFO, "strdup: %m");
						return (NULL);
					}
					rsc->laddress = sc->laddress;	/*dont need to ever clean*/
					rsc->inbuf = inbuf;
					rsc->inbuflen = len;

					rsc->outbuf = outbuf;
					rsc->outbuflen = MAX_BUFSZ;
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


int
proxima_work(struct cfg *cfg, struct sipconn *sc)
{
	struct sipconn *sc_c; 
	struct parsed *packets;
	int len, siperr;

	sc->activity = time(NULL);

	if (parse_payload(sc) == -1) {
		my_syslog(LOG_DEBUG, "parse_payload failure, skip\n");
		return -1;
	}

	if (check_rfc3261(sc, &siperr) < 0) {
		my_syslog(LOG_INFO, "not a SIP packet, or format error %d from %s\n", siperr, sc->address);
		return -1;
	}

	packets = SLIST_FIRST(&sc->packets);
	if (packets == NULL)
		return -1;
	
	len = comp_payload(packets, sc->inbuf, sc->inbuflen);
	if (len < 0) {
		return -1;
	}

	my_syslog(LOG_DEBUG, "entering state logic, state=%d, method=%d", 
		sc->state, sc->method);

	switch (sc->state) {
	case STATE_TRYING:
		if (sc->method == METHOD_INVITE) {
			if (sc->internal && sc->auth == 0) {
				reply_proxy_authenticate(cfg, sc);
			} else if (sc->internal && sc->auth) {
				/* we're not a outgoing proxy so rip it dunn */
				reply_4xx(sc, 404);
				sc->state = STATE_TERMINATED;
			} else {
				if ((sc_c = try_proxy(cfg, sc)) == NULL) {
					/* tear it all down, if this fails */
					reply_internal_error(cfg, sc);
					sc->state = STATE_TERMINATED;
				} else {
					reply_trying(cfg, sc_c);
					sc->state = STATE_PROCEEDING;
				}
			}
		} else if (sc->method == METHOD_REGISTER) {
			if (sc->internal) {
				authenticate(cfg, sc);
			} else {
				/* we're getting a REGISTER from outside */
				reply_4xx(sc, 403);	/* forbidden */
				sc->state = STATE_TERMINATED;
			}
		} else {
			/* reply some negative num? */
			reply_internal_error(cfg, sc);
			sc->state = STATE_TERMINATED;
		}
		break;
	case STATE_PROCEEDING:
		if (sc->method == METHOD_INVITE) {
			if (sc->internal && sc->auth == 0) {
				reply_proxy_authenticate(cfg, sc);
			} else if (sc->internal && sc->auth) {
				reply_4xx(sc, 404);
				sc->state = STATE_TERMINATED;
			} else {
				/* we are entirely external */

				/* this is likely a resend for an INVITE */
				/* XXX tear it down for now */
				reply_internal_error(cfg, sc);
				sc->state = STATE_TERMINATED;
			}
		} else {
			/* shut 'er down */
			sc->state = STATE_TERMINATED;
		}
		break;
	case STATE_COMPLETED:
		sc->state = STATE_TERMINATED;
		break;
	case STATE_TERMINATED:
		sc->state = STATE_TERMINATED;
		break;
	default:
		break;
	}

	if (sc->state == STATE_TERMINATED)
		return -1;

	return 0;
}


/*
 * PARSE_PAYLOAD - from sipdiv.c 
 */

int
parse_payload(struct sipconn *sc)
{
	struct parsed *parser;
	struct sipdata *n1;
	char *nl;

	int newlen, i;
	int header = 0;
	int seencl = 0;
	
	char *payload = sc->inbuf;
	int len = sc->inbuflen;

	SLIST_INIT(&sc->packets);

	parser = (struct parsed *)calloc(1, sizeof(struct parsed));		
	if (parser == NULL) {
		perror("calloc");
		return (-1);
	}

	parser->id = (uint64_t)arc4random();	/* all packets are unique */
	SLIST_INIT(&parser->data);

	do {
		nl = memchr(payload, '\n', len);
		if (nl == NULL) {
			if (len <= 4) {
				n1 = calloc(sizeof(struct sipdata), 1);
				if (n1 == NULL) {
					perror("calloc");
					goto err;
				}

				n1->fields = malloc(len + 1);
				if (n1->fields == NULL) {
					perror("malloc");
					goto err;
				}
				memcpy(n1->fields, payload, len);
				n1->fields[len] = '\0';
				n1->fieldlen = len;
				n1->flags |= SIP_HEAD_FLAG_BODY;
				n1->type = 0;

				sc->method = get_method(parser);
				if (sc->method == -1)
					goto err;

				SLIST_INSERT_HEAD(&parser->data, n1, entries);
				SLIST_INSERT_HEAD(&sc->packets, parser, entries);
				return len;
			} else
				goto err;
		}

		newlen = (nl - payload);
		if (newlen < len) {
			nl++;
			newlen++;
		}

		n1 = calloc(sizeof(struct sipdata), 1);
		if (n1 == NULL) {
			perror("calloc");
			goto err;
		}

		if (seencl == 1) {
			n1->fields = malloc(len + 1);
			if (n1->fields == NULL) {
				perror("malloc");
				goto err;
			}
			memcpy(n1->fields, payload, len);
			n1->fields[len] = '\0';
			n1->fieldlen = len;
			n1->flags |= SIP_HEAD_FLAG_BODY;
			n1->type = 0;
			SLIST_INSERT_HEAD(&parser->data, n1, entries);

			break;
		}

	
		if (header == 0) {
			n1->fields = malloc(newlen + 1);
			if (n1->fields == NULL) {
				perror("malloc");
				goto err;
			}

			memcpy(n1->fields, payload, newlen);
			n1->fields[newlen] = '\0';
			n1->fieldlen = newlen;
			n1->flags |= SIP_HEAD_FLAG_HEADER;
			n1->type = SIP_HEAD_STATUS;
			SLIST_INSERT_HEAD(&parser->data, n1, entries);
			header++;

		} else {
			for (i=0; tokens[i].token != NULL; i++) {
				if (memcmp(payload, tokens[i].token, strlen(tokens[i].token)) == 0) {
					if (tokens[i].type == SIP_HEAD_CONTENTLEN)
						seencl = 1;

					n1->fields = malloc(newlen + 1);
					if (n1->fields == NULL) {
						perror("malloc");
						goto err;
					}
					memcpy(n1->fields, payload, newlen);
					n1->fields[newlen] = '\0';
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
							goto err;
						}

						n1->replacelen = tokenlen;
						memcpy(n1->replace, tokens[i].shortform, strlen(tokens[i].shortform));
						memcpy((&n1->replace[strlen(tokens[i].shortform)]), 
							n1->fields + strlen(tokens[i].token), 
							tokenlen - strlen(tokens[i].shortform));

						n1->flags |= SIP_HEAD_FLAG_COMPACT;
					} 
						
					
					SLIST_INSERT_HEAD(&parser->data, n1, entries);

					break;
				} else if ((tokens[i].shortform != NULL) && memcmp(payload, tokens[i].shortform, strlen(tokens[i].shortform)) == 0) {

					n1->fields = malloc(newlen + 1);
					if (n1->fields == NULL) {
						perror("malloc");
						goto err;
					}
					memcpy(n1->fields, payload, newlen);
					n1->fields[newlen] = '\0';
					n1->fieldlen = newlen;
					n1->flags |= (SIP_HEAD_FLAG_HEADER | SIP_HEAD_FLAG_SHORTFORM);
					n1->type = tokens[i].type;
					
					SLIST_INSERT_HEAD(&parser->data, n1, entries);
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
		if (! find_header(parser, SIP_HEAD_CONTENTTYPE)) {
			add_header(parser, "Content-Type:", 
				" application/sdp\r\n", SIP_HEAD_CONTENTTYPE);
		}
	}

	sc->method = get_method(parser);
	if (sc->method == -1)
		goto err;


	SLIST_INSERT_HEAD(&sc->packets, parser, entries);

	return (0);

err:
	destroy_payload(parser);
	return -1;
}




void
destroy_payload(struct parsed *parser)
{
	struct sipdata *n1;

	if (SLIST_EMPTY(&parser->data))
		return;

	do {
		n1 = SLIST_FIRST(&parser->data);
		if (n1 == NULL)
			break;

		if (n1->fieldlen)
			free(n1->fields);

		if (n1->replacelen)
			free(n1->replace);

		SLIST_REMOVE_HEAD(&parser->data, entries);
		free(n1);
	} while (! SLIST_EMPTY(&parser->data));
}

struct sipdata *
find_header(struct parsed *parser, int type)
{
	struct sipdata *np, *n0;

	SLIST_FOREACH_SAFE(np, &parser->data, entries, n0) {
		if (np->type == type)
			return np;
	}
	return NULL;
}

int
comp_payload(struct parsed *packets, char *buf, int len)
{
	struct sipdata *np;
	char tmpbuf[1024];
	int offset = 0;

	if (len < 1400) /* leave it intact */
		return len;

	/* reconstruct header */

	
	for (int i = 0; tokens[i].type != SIP_HEAD_MAX; i++) {
		SLIST_FOREACH(np, &packets->data, entries) {
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
#if DEBUG
					printf("%s\n", tmpbuf);
#endif
					memcpy(&buf[offset], np->replace, np->replacelen);
					offset += np->replacelen;

				} else {
					if (np->replacelen != 0) {
						memcpy(&tmpbuf, np->replace, np->replacelen);
						tmpbuf[np->replacelen] = '\0';
						if (tmpbuf[np->replacelen - 2] == '\r')
							tmpbuf[np->replacelen - 2] = '\0';
#if DEBUG
						printf("%s\n", tmpbuf);
#endif
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


	SLIST_FOREACH(np, &packets->data, entries) {
		if (!(np->flags & SIP_HEAD_FLAG_BODY))
			continue;

		memcpy(&tmpbuf, np->fields, np->fieldlen);
		tmpbuf[np->fieldlen] = '\0';
		if (tmpbuf[np->fieldlen - 2] == '\r')
			tmpbuf[np->fieldlen - 2] = '\0';
#if DEBUG
		printf("%s\n", tmpbuf);
#endif
		memcpy(&buf[offset], np->fields, np->fieldlen);
		offset += np->fieldlen;
		break;
	}

	return (offset);
}




int
new_payload(struct parsed *packets, char *buf, int len)
{
	struct sipdata *np;
	char tmpbuf[1024];
	int offset = 0;

	/* reconstruct header */

	for (int i = 0; tokens[i].type != SIP_HEAD_MAX; i++) {
		SLIST_FOREACH(np, &packets->data, entries) {
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
#if DEBUG
					printf("%s\n", tmpbuf);
#endif
					memcpy(&buf[offset], np->replace, np->replacelen);
					offset += np->replacelen;

				} else {
					if (np->replacelen != 0) {
						memcpy(&tmpbuf, np->replace, np->replacelen);
						tmpbuf[np->replacelen] = '\0';
						if (tmpbuf[np->replacelen - 2] == '\r')
							tmpbuf[np->replacelen - 2] = '\0';
#if DEBUG
						printf("%s\n", tmpbuf);
#endif
						memcpy(&buf[offset], np->replace, np->replacelen);
						offset += np->replacelen;
					} else {
						memcpy(&tmpbuf, np->fields, np->fieldlen);
						tmpbuf[np->fieldlen] = '\0';
						if (tmpbuf[np->fieldlen - 2] == '\r')
							tmpbuf[np->fieldlen - 2] = '\0';
#if DEBUG
						printf("%s\n", tmpbuf);
#endif
						memcpy(&buf[offset], np->fields, np->fieldlen);
						offset += np->fieldlen;
					}
				}
			}
		}
	}

	/* reconstruct body */


	SLIST_FOREACH(np, &packets->data, entries) {
		if (!(np->flags & SIP_HEAD_FLAG_BODY))
			continue;

		memcpy(&tmpbuf, np->fields, np->fieldlen);
		tmpbuf[np->fieldlen] = '\0';
		if (tmpbuf[np->fieldlen - 2] == '\r')
			tmpbuf[np->fieldlen - 2] = '\0';
#if DEBUG
		printf("%s\n", tmpbuf);
#endif
		memcpy(&buf[offset], np->fields, np->fieldlen);
		offset += np->fieldlen;
		break;
	}

	return (offset);
}

int
typeheader(int type, char *typename, int sz)
{
	int i;

	for (i=0; tokens[i].token != NULL; i++) {
		if (tokens[i].type == type) {

			if (typename != NULL)
				strlcpy(typename, tokens[i].token, sz);

			return (strlen(tokens[i].token));
		}
	}

	return 0;
}


int
copy_header(struct parsed *from, int type, struct parsed *to, int newtype)
{
	struct sipdata *nf, *n0, *n1;
	char s_type[512];
	int len;

	if (newtype == -1)
		newtype = type;

	SLIST_FOREACH_SAFE(nf, &from->data, entries, n0) {
		if (nf->type == type) {
			n1 = calloc(sizeof(struct sipdata), 1);
			if (n1 == NULL) {
				perror("calloc");
				return -1;
			}

			if (nf->replacelen) {
				len = nf->replacelen;
			} else {
				len = nf->fieldlen;
				len -= typeheader(type, NULL, 0); /* trim */
				len += typeheader(newtype, s_type, 
					sizeof(s_type));
			}
			len += 2;

			n1->fields = malloc(len);
			if (n1->fields == NULL) {
				perror("malloc");
				return -1;
			}

			n1->fieldlen = len;
			n1->type = newtype; 

			if (nf->replacelen) {
				strlcpy(n1->fields, nf->replace, 3);
				strlcat(n1->fields, &nf->replace[2], len);
			} else {
				strlcpy(n1->fields, s_type, len);
				strlcat(n1->fields, 
					&nf->fields[typeheader(type, NULL, 0)],
					len);
			}
			
			SLIST_INSERT_HEAD(&to->data, n1, entries);
		}
	}
	
	return 0;
}

void
add_header(struct parsed *parser, char *header, char *contents, int type)
{
	struct sipdata *n1;
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

	SLIST_INSERT_HEAD(&parser->data, n1, entries);
}

struct sipconn *
add_socket(struct cfg *cfg, uint16_t lport, char *rhost, uint16_t rport, int x)
{
	struct addrinfo *res0, *res, hints;
	struct sipconn *sc;
	struct sockaddr_in *psin;
	struct sockaddr_in6 *psin6;
	char laddress[INET6_ADDRSTRLEN];
	socklen_t slen = sizeof(struct sockaddr_storage);
	char branch[16];
	char *p;
	int so, error;

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
			my_syslog(LOG_INFO, "calloc: %m");
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

			if (x == BIND_PORT_INT)
				sc->internal = 1;

			switch (res->ai_family) {
			case AF_INET:
				inet_ntop(AF_INET, &((struct sockaddr_in *)&sc->local)->sin_addr , laddress, sizeof(laddress));
			default:
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sc->local)->sin6_addr , laddress, sizeof(laddress));
			}

			sc->laddress = strdup(laddress);
			if (sc->laddress == NULL) {
				perror("strdup");
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
			sc->state = STATE_TRYING;
		}

		arc4random_buf(&branch, sizeof(branch));
		mybase64_encode(branch, sizeof(branch), sc->branchid, sizeof(sc->branchid));
		memcpy(sc->branchid, BRANCH_MAGIC, strlen(BRANCH_MAGIC));
		p = strchr(sc->branchid, '=');
		if (p != NULL)
			*p = '\0';

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
	int remove = 0;


	now = time(NULL);

	SLIST_FOREACH_SAFE(sc, &cfg->connection, entries, sc0) {
		/* skip all listeners */
		if (sc->state == STATE_LISTEN)
			continue;

		sc->flags = 0;

		/* check/set timers and rearm */
		if (difftime(now, sc->timers[TIMER_A]) > 0) {
			sc->flags |= INVITE_RETRANSMIT;
			SET_TIMER_A(sc, now); 		/* tick */
		}
		if (difftime(now, sc->timers[TIMER_B]) > 0) {
			sc->flags |= INVITE_TIMEOUT;
			SET_TIMER_B(sc, now);
		}
		if (difftime(now, sc->timers[TIMER_C]) > 0) {
			sc->flags |= PROXY_INVITE_TIMEOUT;
			SET_TIMER_C(sc, now);
		}
		if (difftime(now, sc->timers[TIMER_D]) > 0) {
			sc->flags |= RESPONSE_RETRANSMIT0;
			SET_TIMER_D(sc, now);
		}
		if (difftime(now, sc->timers[TIMER_E]) > 0) {
			sc->flags |= NONINVITE_RETRANSMIT;
			SET_TIMER_E(sc, now);
		}
		if (difftime(now, sc->timers[TIMER_F]) > 0) {
			sc->flags |= NONINVITE_TRANSACTION;
			SET_TIMER_F(sc, now);
		}
		if (difftime(now, sc->timers[TIMER_G]) > 0) {
			sc->flags |= INVITE_RESPONSE_RETRANSMIT;
			SET_TIMER_G(sc, now);
		}
		if (difftime(now, sc->timers[TIMER_H]) > 0) {
			sc->flags |= ACK_RECEIPT_TIMEOUT;
			SET_TIMER_H(sc, now);
		}
		if (difftime(now, sc->timers[TIMER_I]) > 0) {
			sc->flags |= ACK_RETRANSMIT;
			SET_TIMER_I(sc, now);
		}
		if (difftime(now, sc->timers[TIMER_J]) > 0) {
			sc->flags |= NONINVITE_REQUEST;
			SET_TIMER_J(sc, now);
		}
		if (difftime(now, sc->timers[TIMER_K]) > 0) {
			sc->flags |= RESPONSE_RETRANSMIT1;
			SET_TIMER_K(sc, now);
		}

		/* do actions */

		if (sc->state == STATE_TRYING) {
			/* this is when we just got the INVITE or NON-INVITE */
			if (sc->flags & INVITE_TIMEOUT) {
				remove = 1;
				sc->flags &= ~(INVITE_TIMEOUT);
			} else if (sc->flags & PROXY_INVITE_TIMEOUT) {
				remove = 1;
				sc->flags &= ~(PROXY_INVITE_TIMEOUT);
			} else if (sc->flags & INVITE_RESPONSE_RETRANSMIT) {
				//retransmit_sc(cfg, sc);	
				sc->flags &= ~(INVITE_RESPONSE_RETRANSMIT);
			}

		} else if (sc->state == STATE_PROCEEDING) {
			/* this is when we're Ringing */
			if (sc->flags & INVITE_TIMEOUT) {
				remove = 1;
				sc->flags &= ~(INVITE_TIMEOUT);
			} else if (sc->flags & PROXY_INVITE_TIMEOUT) {
				remove = 1;
				sc->flags &= ~(PROXY_INVITE_TIMEOUT);
			} 
		} else if (sc->state == STATE_COMPLETED) {
			/* this is when we got ACK'ed to the 4 way handshake */

		} else {
			if ((sc->state == 0) || (sc->state == -1))
				return;
			/* we're in terminated mode delete transaction */
			remove = 1;
		}

		if (remove)
			delete_sc(cfg, sc);
	}
}


void
delete_sc(struct cfg *cfg, struct sipconn *sc)
{		
	struct parsed *packets;

	if (SLIST_EMPTY(&sc->packets)) {
		return;
	}

	do {
		packets = SLIST_FIRST(&sc->packets);
		if (packets == NULL)
			break;
		destroy_payload(packets);	
		SLIST_REMOVE_HEAD(&sc->packets, entries);
		free(packets);
		
	} while (! SLIST_EMPTY(&sc->packets));

	free(sc->address);
	sc->address = NULL;
	SLIST_REMOVE(&cfg->connection, sc, sipconn, entries);

	free(sc);
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
			my_syslog(LOG_INFO, "timing out connection from %s", 
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
			my_syslog(LOG_INFO, "timing out connection from %s", 
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

	my_syslog(LOG_INFO, "dropping state from %s port %u due to ICMP type %s"
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

	my_syslog(LOG_INFO, "IP6 dropping state from %s port %u due to ICMP type %s"
				" code %u", sc->address, ntohs(rsin->sin6_port),  \
				(icmp6.icmp6_type == ICMP6_DST_UNREACH) ? "unreach" : \
				"timex", icmp6.icmp6_code);

	delete_sc(cfg, sc);
}

/*
 * CHECK_RFC3261 - request validation
 *
 * RFC 3261 section 16.3 talks about the following things a proxy needs to do
 * 1. Reasonable Syntax, that's what we're checking here.
 * 2. URI scheme we do sip:// that's it, otherwise 416
 * 3. Max-Forwards is being checked here. A value of 0 means we drop it.
 * 4. Loop Detection (maybe) 
 * 5. Proxy-Require
 * 6. Proxy-Authorization
 *
 */

int
check_rfc3261(struct sipconn *sc, int *siperr)
{
	struct parsed *parser;
	struct sipdata *n1;
	char *status;
	int statuscode;
	uint64_t flags = 0;
	int statuslen = 0;
	int i;

	*siperr = -1;

	if (sc->state == STATE_TERMINATED) {
		my_syslog(LOG_INFO, "trying to reactivate a terminated convo?  sorry");
		return -1;
	}

	parser = SLIST_FIRST(&sc->packets);
	if (parser == NULL)
		return -1;

	SLIST_FOREACH(n1, &parser->data, entries) {
		if (n1->flags & SIP_HEAD_STATUS) {
			status = n1->fields;
			statuslen = n1->fieldlen;
		}
		for (i = 0; i < nitems(ml); i++) {
			if ((n1->flags & SIP_HEAD_FLAG_HEADER) &&
				(ml[i].type == n1->type))
				flags |= ml[i].flag;
		}
	}

#if 0
	if ((statuscode = getstatus(status, statuslen) < 200) &&
		(statuscode > 299))
		return -1;
#endif

	if ((flags & SIP_GENERAL) != SIP_GENERAL)
		return -1;
	else
		*siperr = 200;

	return 0;
}



struct sipconn *
copy_sc(struct cfg *cfg, struct sipconn *sc)
{
	struct sipconn *sc1;

	sc1 = calloc(1, sizeof(struct sipconn));
	if (sc1 == NULL) {
		my_syslog(LOG_INFO, "calloc: %m");
		return NULL;
	}

	memcpy((char *)sc1, (char *)sc, sizeof(struct sipconn));
	sc1->parent = sc;

	return (sc1);
}

struct sipconn *
try_proxy(struct cfg *cfg, struct sipconn *sc)
{
	struct sipconn *sc_copy, *sc_int;
	
	sc_copy = copy_sc(cfg, sc);
	if (sc_copy == NULL) {
		my_syslog(LOG_INFO, "trying to proxy failed!");
		return NULL;
	}

	SLIST_FOREACH(sc_int, &cfg->connection, entries) {
		if ((sc_int->state != STATE_LISTEN) || !(sc_int->internal))
			continue;

		break;
	}

	if (sc_int == NULL) {
		my_syslog(LOG_INFO, "internal error, can't find internal sipconn");
		return NULL;
	}

	memcpy((char *)&sc_copy->local, (char *)&sc_int->local, sizeof(struct sockaddr_storage));
	memcpy((char *)&sc_copy->remote, (char *)&sc_int->remote, sizeof(struct sockaddr_storage));
	
	sc_copy->parent = sc;
	sc_copy->so = sc_int->so;
	sc_copy->state = STATE_TRYING;

	/* now try to send something */

	if (send(sc_copy->so, sc_copy->inbuf, sc_copy->inbuflen, 0) < 0) {
		my_syslog(LOG_INFO, "send: %m");
		return NULL;
	}

	return (sc_copy);	
}

int
reply_trying(struct cfg *cfg, struct sipconn *sc)
{
	char buf[512];
	struct parsed *packet, *from;
	struct sipdata *sd;
	struct sipconn *parent = sc->parent;
	socklen_t sslen;
	int len;
	
	if (parent == NULL)
		return -1;

	from = SLIST_FIRST(&sc->packets);
	if (from == NULL)
		return -1;

	sd = SLIST_FIRST(&from->data);
	if (sd == NULL)
		return -1;

	packet = (struct parsed *)calloc(1, sizeof(struct parsed));		
	if (packet == NULL) {
		perror("calloc");
		return (-1);
	}

	packet->id = (uint64_t)arc4random();
	SLIST_INIT(&packet->data);


	add_header(packet, "SIP/2.0", " 100 Trying", SIP_HEAD_STATUS);

	snprintf(buf, sizeof(buf), " SIP/2.0/UDP %s;branch=%s", 
		sc->laddress, sc->branchid);

	add_header(packet, "Via:", buf, SIP_HEAD_VIA);

	copy_header(from, SIP_HEAD_FROM, packet, SIP_HEAD_TO);

	snprintf(buf, sizeof(buf), " \"Anonymous\" <someone@%s>\r\n", 
		sc->laddress);

	add_header(packet, "From:", buf, SIP_HEAD_FROM);

	copy_header(from, SIP_HEAD_CALLERID, packet, SIP_HEAD_CALLERID);
	copy_header(from, SIP_HEAD_CSEQ, packet, SIP_HEAD_CSEQ);

	snprintf(buf, sizeof(buf), " <sip:anonymous@%s\r\n", sc->laddress);
	add_header(packet, "Contact:", buf, SIP_HEAD_CONTACT);

	add_header(packet, "Content-Type:", " application/sdp\r\n", 
		SIP_HEAD_CONTENTTYPE);

	SLIST_INSERT_HEAD(&sc->packets, packet, entries);

	len = new_payload(packet, sc->outbuf, sc->outbuflen);
	if (len < 0) {
		goto out;
	}
	
	sslen = (parent->remote.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	if (sendto(parent->so, sc->outbuf, len, 0, (struct sockaddr *)&parent->remote, sslen) < 0) {
		goto out;
	}

	sc->activity = time(NULL);
	parent->activity = sc->activity;
	SET_ALL_TIMERS(sc, sc->activity);

	free(packet);
	return 0;

out:
	free(packet);
	return -1;

}

/*
 * reply a 5xx (500) code 
 */

int
reply_internal_error(struct cfg *cfg, struct sipconn *sc)
{
	char buf[512];
	struct parsed *packet, *from;
	struct sipdata *sd;
	struct sipconn *parent = sc->parent;
	socklen_t sslen;
	int len;
	
	if (parent == NULL)
		return -1;

	from = SLIST_FIRST(&sc->packets);
	if (from == NULL)
		return -1;

	sd = SLIST_FIRST(&from->data);
	if (sd == NULL)
		return -1;

	packet = (struct parsed *)calloc(1, sizeof(struct parsed));		
	if (packet == NULL) {
		perror("calloc");
		return (-1);
	}

	packet->id = (uint64_t)arc4random();
	SLIST_INIT(&packet->data);


	add_header(packet, "SIP/2.0", " 500 Server Internal Error", SIP_HEAD_STATUS);

	snprintf(buf, sizeof(buf), " SIP/2.0/UDP %s", sc->laddress);
	add_header(packet, "Via:", buf, SIP_HEAD_VIA);

	copy_header(from, SIP_HEAD_FROM, packet, SIP_HEAD_TO);
	copy_header(from, SIP_HEAD_TO, packet, SIP_HEAD_FROM);
	copy_header(from, SIP_HEAD_CALLERID, packet, SIP_HEAD_CALLERID);
	copy_header(from, SIP_HEAD_CSEQ, packet, SIP_HEAD_CSEQ);
	copy_header(from, SIP_HEAD_CONTACT, packet, SIP_HEAD_CONTACT);


	SLIST_INSERT_HEAD(&sc->packets, packet, entries);

	len = new_payload(packet, sc->outbuf, sc->outbuflen);
	if (len < 0) {
		goto out;
	}
	
	sslen = (parent->remote.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	if (sendto(parent->so, sc->outbuf, len, 0, (struct sockaddr *)&parent->remote, sslen) < 0) {
		goto out;
	}

	sc->activity = time(NULL);
	parent->activity = sc->activity;

	free(packet);
	return 0;
out:
	free(packet);
	return -1;

}

/*
 * reply a 4xx error 
 */

int
reply_4xx(struct sipconn *sc, int code)
{
	char buf[512];
	struct parsed *packet, *from;
	struct sipdata *sd;
	struct sipconn *parent = sc->parent;
	socklen_t sslen;
	int len;
	
	if (parent == NULL)
		return -1;

	from = SLIST_FIRST(&sc->packets);
	if (from == NULL)
		return -1;

	sd = SLIST_FIRST(&from->data);
	if (sd == NULL)
		return -1;

	packet = (struct parsed *)calloc(1, sizeof(struct parsed));		
	if (packet == NULL) {
		perror("calloc");
		return (-1);
	}

	packet->id = (uint64_t)arc4random();
	SLIST_INIT(&packet->data);


	snprintf(buf, sizeof(buf), " %d %s", code, statuscode_s(code));
	add_header(packet, "SIP/2.0", buf, SIP_HEAD_STATUS);

	snprintf(buf, sizeof(buf), " SIP/2.0/UDP %s", sc->laddress);
	add_header(packet, "Via:", buf, SIP_HEAD_VIA);

	copy_header(from, SIP_HEAD_FROM, packet, SIP_HEAD_TO);
	copy_header(from, SIP_HEAD_TO, packet, SIP_HEAD_FROM);
	copy_header(from, SIP_HEAD_CALLERID, packet, SIP_HEAD_CALLERID);
	copy_header(from, SIP_HEAD_CSEQ, packet, SIP_HEAD_CSEQ);
	copy_header(from, SIP_HEAD_CONTACT, packet, SIP_HEAD_CONTACT);

	SLIST_INSERT_HEAD(&sc->packets, packet, entries);

	len = new_payload(packet, sc->outbuf, sc->outbuflen);
	if (len < 0) {
		goto out;
	}
	
	sslen = (parent->remote.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	if (sendto(parent->so, sc->outbuf, len, 0, (struct sockaddr *)&parent->remote, sslen) < 0) {
		goto out;
	}

	sc->activity = time(NULL);
	parent->activity = sc->activity;

out:
	free(packet);
	return -1;

}

int
reply_proxy_authenticate(struct cfg *cfg, struct sipconn *sc)
{
	char buf[512];
	char *sbuf[2];
	struct parsed *packet, *from;
	struct sipdata *sd;
	struct sipconn *parent = sc->parent;
	socklen_t sslen;
	int len, i;
	
	if (parent == NULL)
		return -1;

	from = SLIST_FIRST(&sc->packets);
	if (from == NULL)
		return -1;

	sd = SLIST_FIRST(&from->data);
	if (sd == NULL)
		return -1;

	packet = (struct parsed *)calloc(1, sizeof(struct parsed));		
	if (packet == NULL) {
		perror("calloc");
		return (-1);
	}

	packet->id = (uint64_t)arc4random();
	SLIST_INIT(&packet->data);

	add_header(packet, "SIP/2.0", " 407 Proxy Authentication Required", SIP_HEAD_STATUS);

	snprintf(buf, sizeof(buf), " SIP/2.0/UDP %s;branch=%s", 
		sc->laddress, sc->branchid);
	add_header(packet, "Via:", buf, SIP_HEAD_VIA);

	copy_header(from, SIP_HEAD_FROM, packet, SIP_HEAD_TO);

	snprintf(buf, sizeof(buf), " \"Anonymous\" <someone@%s>;tag=%lld\r\n", 
		sc->laddress, packet->id);
	add_header(packet, "From:", buf, SIP_HEAD_FROM);

	copy_header(from, SIP_HEAD_CALLERID, packet, SIP_HEAD_CALLERID);
	copy_header(from, SIP_HEAD_CSEQ, packet, SIP_HEAD_CSEQ);

	snprintf(buf, sizeof(buf), " <sip:anonymous@%s\r\n", sc->laddress);
	add_header(packet, "Contact:", buf, SIP_HEAD_CONTACT);

	/* make some temp bufs */
	for (i = 0; i < 2; i++) {
		sbuf[i] = malloc_conceal(64);
		if (sbuf[i] == NULL)
			goto out;
	}

	sc->nonce = calloc_conceal(1, 32);
	if (sc->nonce == NULL)
		goto out;
	arc4random_buf(sc->nonce, 32);
	mybase64_encode((char *)sc->nonce, 32, sbuf[BUF_NONCE], 64);
	if (sc->opaque == NULL) {
		sc->opaque = malloc_conceal(32);
		if (sc->opaque == NULL) {
			freezero(sbuf[BUF_NONCE], 64);
			freezero(sbuf[BUF_OPAQUE], 64);
			goto out;
		}
		arc4random_buf(sc->opaque, 32);
	}

	mybase64_encode((char *)sc->opaque, 32, sbuf[BUF_OPAQUE], 64);

	snprintf(buf, sizeof(buf), " Digest realm=\"%s\" "
		"domain=\"sip:%s\", qop=\"auth\", nonce=\"%s\", "
		"opaque=\"%s\", stale=FALSE, algorithm=%s\r\n",
		cfg->mydomain, cfg->myname, sbuf[BUF_NONCE], sbuf[BUF_OPAQUE],
		(sc->alg == ALG_MD5) ? "MD5" : "SHA-256");

	/* clean up temp bufs */
	for (i = 0; i < 2; i++) {
		freezero(sbuf[i], 64);
	}

      	add_header(packet, "Proxy-Authenticate:", buf, SIP_HEAD_PROXYAUTHEN);

	add_header(packet, "Content-Type:", " application/sdp\r\n", 
		SIP_HEAD_CONTENTTYPE);

	SLIST_INSERT_HEAD(&sc->packets, packet, entries);

	len = new_payload(packet, sc->outbuf, sc->outbuflen);
	if (len < 0) {
		goto out;
	}
	
	sslen = (parent->remote.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	if (sendto(parent->so, sc->outbuf, len, 0, (struct sockaddr *)&parent->remote, sslen) < 0) {
		goto out;
	}

	sc->activity = time(NULL);
	parent->activity = sc->activity;

	free(packet);
	return 0;
out:
	free(packet);
	return -1;

}

/*
 * CALCULATE HA1 - creates H(username|":"|realm|":"|password)
 */

u_char *
calculate_ha1(char *u, char *p, char *domain, int alg, size_t *ha1_len)
{
	SHA256_CTX sha256;
	MD5_CTX md5;
	u_char *ha1;

	/* SHA512 not supported */
	if (alg == ALG_SHA5)
		return NULL;

	ha1 = malloc_conceal(128);
	if (ha1 == NULL)
		return NULL;

	switch (alg) {
	case ALG_SHA2:
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, u, strlen(u));
		SHA256_Update(&sha256, ":", 1);
		SHA256_Update(&sha256, p, strlen(p));
		SHA256_Update(&sha256, ":", 1);
		SHA256_Update(&sha256, domain, strlen(domain));
		SHA256_Final(ha1, &sha256);
		*ha1_len = (256 / 8);
		break;
	case ALG_MD5:
		MD5_Init(&md5);
		MD5_Update(&md5, u, strlen(u));
		MD5_Update(&md5, ":", 1);
		MD5_Update(&md5, p, strlen(p));
		MD5_Update(&md5, ":", 1);
		MD5_Update(&md5, domain, strlen(domain));
		MD5_Final(ha1, &md5);
		*ha1_len = 16;
		break;
	default:
		free(ha1);
		return NULL;
		break;
	}

	explicit_bzero(&sha256, sizeof(sha256));
	explicit_bzero(&md5, sizeof(md5));

	return (ha1);
}

u_char *
calculate_ha2(char *method, int algorithm, char *requesturi, size_t *ha2_len)
{
	SHA256_CTX sha256;
	MD5_CTX md5;
	u_char *ha2;

	/* SHA512 not supported */
	if (algorithm == ALG_SHA5)
		return NULL;

	ha2 = malloc_conceal(128);
	if (ha2 == NULL)
		return NULL;

	switch (algorithm) {
	case ALG_SHA2:
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, method, strlen(method));
		SHA256_Update(&sha256, ":", 1);
		SHA256_Update(&sha256, requesturi, strlen(requesturi));
		SHA256_Final(ha2, &sha256);
		*ha2_len = (256 / 8);
		break;
	case ALG_MD5:
		MD5_Init(&md5);
		MD5_Update(&md5, method, strlen(method));
		MD5_Update(&md5, ":", 1);
		MD5_Update(&md5, requesturi, strlen(requesturi));
		MD5_Final(ha2, &md5);
		*ha2_len = 16;
		break;
	default:
		free(ha2);
		return NULL;
		break;
	}

	explicit_bzero(&sha256, sizeof(sha256));
	explicit_bzero(&md5, sizeof(md5));

	return (ha2);
}

struct sipconn *
authenticate(struct cfg *cfg, struct sipconn *sc)
{
	struct parsed *packet, *from;
	struct sipdata *sd;
	struct sipconn *newsc, *parent;
	char buf[512];
	char *inputstring;
	char **ap = NULL, *argv[20];
	char *response;
	int response_len;
	int len, i;
	socklen_t sslen;

	SHA256_CTX sha256;
	MD5_CTX md5;

	struct {
		int type;
		#define TAG_DIGEST		0
		#define TAG_USERNAME		1
		#define TAG_REALM		2
		#define TAG_NONCE		3
		#define TAG_RESPONSE		4
		#define TAG_URI			5
		#define TAG_QOP			6
		#define TAG_NC			7
		#define TAG_CNONCE		8
		#define TAG_ALG			9
		#define TAG_OPAQUE		10
		char *tag;
		char *value;
		int len;
	} authtok[] = {
		{ TAG_DIGEST, "Digest", NULL, 0 },
		{ TAG_USERNAME, "username=\"", NULL, 0 },
		{ TAG_REALM, "realm=\"", NULL, 0 },
		{ TAG_NONCE, "nonce=\"", NULL, 0 },
		{ TAG_RESPONSE, "response=\"", NULL, 0 },
		{ TAG_URI, "uri=\"", NULL, 0 },
		{ TAG_QOP, "qop=", NULL, 0 },
		{ TAG_NC, "nc=", NULL, 0 },
		{ TAG_CNONCE, "cnonce=\"", NULL, 0 },
		{ TAG_ALG, "algorithm=\"", NULL, 0 },
		{ TAG_OPAQUE, "opaque=\"", NULL, 0 }
	};
	
	from = SLIST_FIRST(&sc->packets);
	if (from == NULL)
		return NULL;

	sd = SLIST_FIRST(&from->data);
	if (sd == NULL)
		return NULL;

	if ((sd = find_header(from, SIP_HEAD_PROXYAUTHOR)) == NULL)
		return NULL;

	/* for preservation */
	inputstring = calloc_conceal(1, sd->fieldlen + 1);
	if (inputstring == NULL) {
		my_syslog(LOG_INFO, "calloc_conceal: %m");
		return NULL;
	}

	memcpy(inputstring, sd->fields, sd->fieldlen);

	/* tokenize */
	for (ap = argv; ap < &argv[19] &&
		(*ap = strsep(&inputstring, " \t")) != NULL;) {
			for (i = 0; i < nitems(authtok); i++) {
				if (strncmp(authtok[i].tag, *ap, \
					strlen(authtok[i].tag)) == 0) {
					*ap += strlen(authtok[i].tag);
					len = strlen(*ap);
					if (*ap[len - 1] == ',')
						len--;
					if (*ap[len - 1] == '"')
						len--;
					*ap[len] = '\0';

					authtok[i].value = malloc_conceal(len);
					if (authtok[i].value == NULL) {
						my_syslog(LOG_INFO, "malloc: %m");
						goto cleantok;
					}

					strlcpy(authtok[i].value, *ap, len);
					authtok[i].len = len;
				}
			}
			if (**ap != '\0')
				ap++;
	}
	*ap = NULL;
	freezero(inputstring, sd->fieldlen + 1);
	
	/*
	 * we don't have a child copy, make one, and work on it further
	 */
	if (sc->parent == NULL) {
		newsc = copy_sc(cfg, sc);
		if (newsc == NULL)
			goto cleantok;

		parent = sc;
		newsc->parent = sc;
		sc = newsc;
	}

	if (authtok[TAG_NONCE].len) {
		sc->nonce_len = authtok[TAG_NONCE].len;
		sc->nonce = authtok[TAG_NONCE].value;
	}
	if (authtok[TAG_CNONCE].len) {
		sc->cnonce_len = authtok[TAG_CNONCE].len;
		sc->cnonce = authtok[TAG_CNONCE].value;
	}
	if (authtok[TAG_NC].len)
		sc->nc = strtoull(authtok[TAG_NC].value, NULL, 16);

	if (authtok[TAG_OPAQUE].len) {
		sc->opaque_len = authtok[TAG_OPAQUE].len;
		sc->opaque = authtok[TAG_OPAQUE].value;
	}

	if (authtok[TAG_ALG].len) {
		sc->alg = ALG_MD5;

		if (strncmp(authtok[TAG_ALG].value, "MD5", 3) == 0)
			sc->alg = ALG_MD5;
		if (strncmp(authtok[TAG_ALG].value, "SHA-256", 7) == 0)
				sc->alg = ALG_SHA2;
	} else {
		sc->alg = ALG_SHA2;
	}

	if (authtok[TAG_QOP].len) {
		if (strstr(authtok[TAG_QOP].value, "auth-int") == NULL)
			sc->qop = 0;		/* no integrity, just "auth" */
		else
			sc->qop = 1;
	}

	if (authtok[TAG_URI].len == 0) {
		goto cleantok;
	}

	
	sc->ha2 = calculate_ha2("Digest", sc->alg, authtok[TAG_URI].value, \
			&sc->ha2_len);

	response = malloc_conceal(128);
	if (response == NULL)
		goto cleantok;

	switch (sc->alg) {
	case ALG_MD5:
		MD5_Init(&md5);
		MD5_Update(&md5, sc->ha1, sc->ha1_len);
		//MD5_Update(&md5, ":", 1);
		MD5_Update(&md5, sc->nonce, sc->nonce_len);
		MD5_Update(&md5, ":", 1);
		MD5_Update(&md5, authtok[TAG_NC].value, authtok[TAG_NC].len);
		MD5_Update(&md5, ":", 1);
		MD5_Update(&md5, sc->cnonce, sc->cnonce_len);
		MD5_Update(&md5, ":", 1);
		MD5_Update(&md5, authtok[TAG_QOP].value,authtok[TAG_QOP].len);
		MD5_Update(&md5, ":", 1);
		MD5_Update(&md5, sc->ha2, sc->ha2_len);
		MD5_Final(response, &md5);
		response_len = 16;

		break;
	case ALG_SHA2:
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, sc->ha1, sc->ha1_len);
		//SHA256_Update(&sha256, ":", 1);
		SHA256_Update(&sha256, sc->nonce, sc->nonce_len);
		SHA256_Update(&sha256, ":", 1);
		SHA256_Update(&sha256, authtok[TAG_NC].value, authtok[TAG_NC].len);
		SHA256_Update(&sha256, ":", 1);
		SHA256_Update(&sha256, sc->cnonce, sc->cnonce_len);
		SHA256_Update(&sha256, ":", 1);
		SHA256_Update(&sha256, authtok[TAG_QOP].value,authtok[TAG_QOP].len);
		SHA256_Update(&sha256, ":", 1);
		SHA256_Update(&sha256, sc->ha2, sc->ha2_len);
		SHA256_Final(response, &sha256);
		response_len = (256 / 8);

		break;
	default:
		goto cleantok;
		break;
	}

	len = mybase64_encode(response, response_len, buf, sizeof(buf));
	if ((len == authtok[TAG_RESPONSE].len) && \
		(strcmp(authtok[TAG_RESPONSE].value, buf) == 0)) {
		sc->auth = 1;
	} else
		sc->auth = 0;
	
	explicit_bzero(&buf, sizeof(buf));
	explicit_bzero(&sha256, sizeof(sha256));
	explicit_bzero(&md5, sizeof(md5));

	freezero(response, 128);
	
	packet = (struct parsed *)calloc_conceal(1, sizeof(struct parsed));		
	if (packet == NULL) {
		perror("calloc");
		goto cleantok;
	}

	packet->id = (uint64_t)arc4random();
	SLIST_INIT(&packet->data);

	if (sc->auth == 1)
		add_header(packet, "SIP/2.0", " 200 OK", SIP_HEAD_STATUS);

	/* fill in */

	snprintf(buf, sizeof(buf), " SIP/2.0/UDP %s;branch=%s", 
		sc->laddress, sc->branchid);
	add_header(packet, "Via:", buf, SIP_HEAD_VIA);

	copy_header(from, SIP_HEAD_FROM, packet, SIP_HEAD_TO);
	copy_header(from, SIP_HEAD_TO, packet, SIP_HEAD_FROM);
	copy_header(from, SIP_HEAD_CALLERID, packet, SIP_HEAD_CALLERID);
	copy_header(from, SIP_HEAD_CSEQ, packet, SIP_HEAD_CSEQ);
	copy_header(from, SIP_HEAD_CONTACT, packet, SIP_HEAD_CONTACT);

	SLIST_INSERT_HEAD(&sc->packets, packet, entries);

	len = new_payload(packet, sc->outbuf, sc->outbuflen);
	if (len < 0) {
		goto out;
	}
	
	sslen = (parent->remote.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	if (sendto(parent->so, sc->outbuf, len, 0, (struct sockaddr *)&parent->remote, sslen) < 0) {
		goto out;
	}

	/* XXX use new timers */
	sc->activity = time(NULL);
	parent->activity = sc->activity;

out:
	for (i = 0; i < nitems(authtok); i++) {
		if (authtok[i].len)
			freezero(authtok[i].value, authtok[i].len);
	}

	freezero(packet, sizeof(struct parsed));
	return (sc);

cleantok:
	for (i = 0; i < nitems(authtok); i++) {
		if (authtok[i].len)
			freezero(authtok[i].value, authtok[i].len);
	}

	return NULL;
}


char *
statuscode_s(int code)
{
	struct statusc *sc = statuscodes;

	for (; sc->statuscode != -1; sc++) {
		if (sc->statuscode == code)
			return (sc->message);
	}

	return ("unknown");
}

void
my_syslog(int priority, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (debug) {
		vfprintf(stderr, fmt, ap);
	}
	if (priority != LOG_DEBUG)
		vsyslog(priority, fmt, ap);	

	va_end(ap);
}

int
get_method(struct parsed *parser)
{
	struct sipdata *status;
	int ret = -1;
	int i;

	status = find_header(parser, SIP_HEAD_STATUS);
	if (status != NULL) {
		for (i = 0; i < nitems(methods); i++) {
			if (strncmp(status->fields, methods[i].method, \
					strlen(methods[i].method)) == 0) {

				ret = methods[i].meth;

				my_syslog(LOG_DEBUG, 
					"method is %s type %d\n", 
					methods[i].method, ret);

				break;
			}
		}
	} 

	return ret;
}
