/* 
 * Copyright (c) 2024 Peter J. Philipp
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


/* from page 219 */

#ifndef _RFC3261_H
#define _RFC3261_H

struct {
	char mline[40];
} ml[]  =  {
	{"Accept"},
	{"Accept-Encoding"},
	{"Accept-Language"},
	{"Alert-Info"},
	{"Allow"},
	{"Authentication-Info"},
	{"Authorization"},
	{"Call-ID"},
	{"Call-Info"},
	{"Contact"},
	{"Content-Disposition"},
	{"Content-Encoding"},
	{"Content-Language"},
	{"Content-Length"},
	{"Content-Type"},
	{"CSeq"},
	{"Date"},
	{"Error-Info"},
	{"Expires"},
	{"From"},
	{"In-Reply-To"},
	{"Max-Forwards"},
	{"MIME-Version"},
	{"Min-Expires"},
	{"Organization"},
	{"Priority"},
	{"Proxy-Authenticate"},
	{"Proxy-Authorization"},
	{"Proxy-Require"},
	{"Record-Route"},
	{"Reply-To"},
	{"Require"},
	{"Retry-After"},
	{"Route"},
	{"Server"},
	{"Subject"},
	{"Supported"},
	{"Timestamp"},
	{"To"},
	{"Unsupported"},
	{"User-Agent"},
	{"Via"},
	{"Warning"},
	{"WWW-Authenticate"}
};


struct {
	char method[16];
	int meth;
#define INVITE			1
#define ACK			2
#define OPTIONS			3
#define BYE			4
#define CANCEL			5
#define REGISTER		6
} methods[] = {
	{"INVITE", INVITE},
	{"ACK", ACK},
	{"OPTIONS", OPTIONS},
	{"BYE", BYE},
	{"CANCEL", CANCEL},
	{"REGISTER", REGISTER}
};
		

#define INFORMATIONAL		1
#define REDIRECTION		2
#define SUCCESS			3
#define CLIENTERROR		4
#define SERVERERROR		5
#define GLOBALFAILURE		6

struct {
	int	statuscode;
	char 	*statuscode_s;
	char 	*class;
	char	*message;
} statuscodes[] = {
	{100, "100",  INFORMATIONAL,  	"Trying"},
	{180, "180",  INFORMATIONAL,  	"Ringing"},
	{181, "181",  INFORMATIONAL,  	"Call Is Being Forwarded"},
	{182, "182",  INFORMATIONAL,  	"Queued"},
	{183, "183",  INFORMATIONAL,  	"Session Progress"},
	{200, "200",  SUCCESS  		"OK"},
	{300, "300",  REDIRECTION,  	"Multiple Choices"},
	{301, "301",  REDIRECTION,  	"Moved Permanently"},
	{302, "302",  REDIRECTION,  	"Moved Temporarily"},
	{305, "305",  REDIRECTION,  	"Use Proxy"},
	{380, "380",  REDIRECTION,  	"Alternative Service"},
	{400, "400",  CLIENTERROR,  	"Bad Request"},
	{401, "401",  CLIENTERROR, 	"Unauthorized"},
	{402, "402",  CLIENTERROR,  	"Payment Required"},
	{403, "403",  CLIENTERROR,	"Forbidden"},
	{404, "404",  CLIENTERROR,  	"Not Found"},
	{405, "405",  CLIENTERROR,  	"Method Not Allowed"},
	{406, "406",  CLIENTERROR,  	"Not Acceptable"},
	{407, "407",  CLIENTERROR,  	"Proxy Authentication Required"},
	{408, "408",  CLIENTERROR,  	"Request Timeout"},
	{410, "410",  CLIENTERROR,  	"Gone"},
	{413, "413",  CLIENTERROR,  	"Request Entity Too Large"},
	{414, "414",  CLIENTERROR,  	"Request-URI Too Large"},
	{415, "415",  CLIENTERROR,  	"Unsupported Media Type"},
	{416, "416",  CLIENTERROR,  	"Unsupported URI Scheme"},
	{420, "420",  CLIENTERROR,  	"Bad Extension"},
	{421, "421",  CLIENTERROR,  	"Extension Required"},
	{423, "423",  CLIENTERROR,  	"Interval Too Brief"},
	{480, "480",  CLIENTERROR,  	"Temporarily not available"},
	{481, "481",  CLIENTERROR,  	"Call Leg/Transaction Does Not Exist"},
	{482, "482",  CLIENTERROR,  	"Loop Detected"},
	{483, "483",  CLIENTERROR,  	"Too Many Hops"},
	{484, "484",  CLIENTERROR,  	"Address Incomplete"},
	{485, "485",  CLIENTERROR,  	"Ambiguous"},
	{486, "486",  CLIENTERROR,  	"Busy Here"},
	{487, "487",  CLIENTERROR,  	"Request Terminated"},
	{488, "488",  CLIENTERROR,  	"Not Acceptable Here"},
	{491, "491",  CLIENTERROR,  	"Request Pending"},
	{493, "493",  CLIENTERROR,  	"Undecipherable"},
	{500, "500",  SERVERERROR, 	"Internal Server Error"},
	{501, "501",  SERVERERROR, 	"Not Implemented"},
	{502, "502",  SERVERERROR, 	"Bad Gateway"},
	{503, "503",  SERVERERROR, 	"Service Unavailable"},
	{504, "504",  SERVERERROR, 	"Server Time-out"},
	{505, "505",  SERVERERROR, 	"SIP Version not supported"},
	{513, "513",  SERVERERROR, 	"Message Too Large"},
	{600, "600",  GLOBALFAILURE, 	"Busy Everywhere"},
	{603, "603",  GLOBALFAILURE, 	"Decline"},
	{604, "604",  GLOBALFAILURE, 	"Does not exist anywhere"},
	{606, "606",  GLOBALFAILURE, 	"Not Acceptable"},
	{-1, NULL, NULL, NULL }
};

#endif /* _RFC3261_H */
