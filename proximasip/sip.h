#ifndef _SIP_H
#define _SIP_H

#define SIP_HEAD_STATUS		0		/* status line */
#define SIP_HEAD_FROM		1		/* From: */
#define SIP_HEAD_TO		2		/* To: */
#define SIP_HEAD_VIA		3		/* Via: */
#define SIP_HEAD_CALLERID	4		/* Caller-ID: */
#define SIP_HEAD_USERAGENT	5		/* User-Agent: */
#define SIP_HEAD_CONTENTTYPE	6		/* Content-Type: */
#define SIP_HEAD_ACCEPTCONTACT	7		/* Accept-Contact: */
#define SIP_HEAD_MAXFORWARDS	8		/* Max-Forwards: */
#define SIP_HEAD_CONTACT		9		/* Contact: */
#define SIP_HEAD_CSEQ		10		/* CSeq: */
#define SIP_HEAD_SUPPORTED	11		/* Supported: */
#define SIP_HEAD_ALLOW		12		/* Allow: */
#define SIP_HEAD_ALLOWEVENTS	13		/* Allow-Events: */
#define SIP_HEAD_EVENT		14
#define	SIP_HEAD_REFERTO		15
#define SIP_HEAD_REFERREDBY	16
#define SIP_HEAD_REJECTCONTACT	17
#define	SIP_HEAD_SUBJECT		18
#define	SIP_HEAD_ALERTINFO	19
#define	SIP_HEAD_CALLINFO	20
#define	SIP_HEAD_DATE		21
#define	SIP_HEAD_ERRORINFO	22
#define	SIP_HEAD_MAXBREADTH	23
#define	SIP_HEAD_ORGANIZATION	24
#define	SIP_HEAD_PRIORITY	25
#define	SIP_HEAD_PROXYAUTHEN	26
#define	SIP_HEAD_PROXYAUTHOR	27
#define	SIP_HEAD_PROXYREQ	28
#define	SIP_HEAD_RECORDROUTE	29
#define SIP_HEAD_EXPIRES		30
#define	SIP_HEAD_REQUIRE		31
#define	SIP_HEAD_ROUTE		32
#define	SIP_HEAD_WWWAUTH		33
#define	SIP_HEAD_SECURECLIENT	34
#define	SIP_HEAD_SECUREVERIFY	35
#define	SIP_HEAD_SECURESERVER	36
#define	SIP_HEAD_ANSWERMODE	37
#define	SIP_HEAD_PRIVANSWERMODE	38
#define	SIP_HEAD_HISTORYINFO	39
#define	SIP_HEAD_PATH		40
#define	SIP_HEAD_IDENTITY	41
#define	SIP_HEAD_IDENTITYINFO	42
#define	SIP_HEAD_PASSERTEDID	43
#define	SIP_HEAD_REASON		44
#define	SIP_HEAD_RESOURCEPRIO	45
#define	SIP_HEAD_AUTHINFO	46
#define SIP_HEAD_XAUSERAGENT	47
#define SIP_HEAD_XACONTACT	48
#define SIP_HEAD_CONTENTENC	49
#define SIP_HEAD_CONTENTLEN	50
#define SIP_HEAD_ACCEPT		51
#define SIP_HEAD_ACCEPTENC	52
#define SIP_HEAD_ACCEPTLANG	53
#define SIP_HEAD_AUTHORIZATION	54
#define SIP_HEAD_MAX		55


struct tok {
	int type;
	char *token;
	char *shortform;
} tokens[] = {
	{ SIP_HEAD_STATUS, "YCVFDSAFEWQFQF", NULL },
	{ SIP_HEAD_VIA, "Via:" , "v:" },
	{ SIP_HEAD_ROUTE , "Route:", NULL },
	{ SIP_HEAD_FROM, "From:" , "f:" },
	{ SIP_HEAD_TO, "To:", "t:" },
	{ SIP_HEAD_CALLERID, "Call-ID:", "i:" },
	{ SIP_HEAD_CSEQ, "CSeq:", NULL },
	{ SIP_HEAD_CONTACT, "Contact:", "m:" },
	{ SIP_HEAD_AUTHORIZATION, "Authorization:", NULL },
	{ SIP_HEAD_MAXFORWARDS, "Max-Forwards:", NULL },
	{ SIP_HEAD_EXPIRES , "Expires:" , NULL},
	{ SIP_HEAD_USERAGENT, "User-Agent:", NULL },
	{ SIP_HEAD_SUPPORTED, "Supported:", NULL },
	{ SIP_HEAD_ALLOWEVENTS, "Allow-Events:" , "u:" },
	{ SIP_HEAD_ALLOW, "Allow:", NULL },
	{ SIP_HEAD_ACCEPT , "Accept:", NULL },
	{ SIP_HEAD_ACCEPTENC , "Accept-Encoding:", NULL },
	{ SIP_HEAD_ACCEPTCONTACT, "Accept-Contact:", "a:" },
	{ SIP_HEAD_EVENT, "Event:" , "o:" },
	{ SIP_HEAD_REFERTO, "Refer-To:" , "r:" },
	{ SIP_HEAD_REFERREDBY, "Referred-By:", "b:" },
	{ SIP_HEAD_REJECTCONTACT, "Reject-Contact:", "j:" },
	{ SIP_HEAD_SUBJECT, "Subject:", "s:" },
	{ SIP_HEAD_ALERTINFO , "Alert-Info:", NULL },
	{ SIP_HEAD_CALLINFO , "Call-Info:", NULL },
	{ SIP_HEAD_DATE , "Date:", NULL },
	{ SIP_HEAD_ERRORINFO , "Error-Info:", NULL },
	{ SIP_HEAD_MAXBREADTH , "Max-Breadth:", NULL },
	{ SIP_HEAD_ORGANIZATION , "Organization:", NULL },
	{ SIP_HEAD_PRIORITY , "Priority:", NULL },
	{ SIP_HEAD_PROXYAUTHEN , "Proxy-Authenticate:", NULL },
	{ SIP_HEAD_PROXYAUTHOR , "Proxy-Authorization:", NULL },
	{ SIP_HEAD_PROXYREQ , "Proxy-Require:", NULL },
	{ SIP_HEAD_RECORDROUTE , "Record-Route:", NULL },
	{ SIP_HEAD_REASON , "Reason:", NULL },
	{ SIP_HEAD_REQUIRE , "Require:", NULL },
	{ SIP_HEAD_WWWAUTH , "WWW-Authenticate:", NULL },
	{ SIP_HEAD_SECURECLIENT , "Security-Client:", NULL },
	{ SIP_HEAD_SECUREVERIFY , "Security-Verify:" , NULL },
	{ SIP_HEAD_SECURESERVER , "Secure-Server:" , NULL },
	{ SIP_HEAD_ANSWERMODE , "Answer-Mode:" , NULL },
	{ SIP_HEAD_PRIVANSWERMODE , "Priv-Answer-Mode:" , NULL },
	{ SIP_HEAD_HISTORYINFO , "History-Info:" , NULL },
	{ SIP_HEAD_PATH , "Path:" , NULL },
	{ SIP_HEAD_IDENTITY , "Identity:" , NULL },
	{ SIP_HEAD_IDENTITYINFO , "Identity-Info:" , NULL },
	{ SIP_HEAD_PASSERTEDID , "P-Asserted-Identity:" , NULL },
	{ SIP_HEAD_RESOURCEPRIO , "Resource-Priority:" , NULL },
	{ SIP_HEAD_AUTHINFO , "Auth-Info:" , NULL },
	{ SIP_HEAD_XAUSERAGENT , "X-A-User-Agent:" , NULL },
	{ SIP_HEAD_XACONTACT , "X-A-Contact:" , NULL },
	{ SIP_HEAD_ACCEPTLANG , "Accept-Language:" , NULL },
	{ SIP_HEAD_CONTENTENC , "Content-Encoding:", "e:" },
	{ SIP_HEAD_CONTENTTYPE, "Content-Type:" , "c:" },
	{ SIP_HEAD_CONTENTLEN , "Content-Length:", "l:" },
	{ SIP_HEAD_MAX, NULL, NULL }
};

#endif /* _SIP_H */
