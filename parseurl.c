/*  RTMPDump
 *  Copyright (C) 2009 Andrej Stepanchuk
 *  Copyright (C) 2009 Howard Chu
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with RTMPDump; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/copyleft/gpl.html
 *
 */

#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <ctype.h>

#include "log.h"
#include "parseurl.h"

#define RTMP_PROTOCOL_UNDEFINED	-1
#define RTMP_PROTOCOL_RTMP      0
#define RTMP_PROTOCOL_RTMPT     1 // not yet supported
#define RTMP_PROTOCOL_RTMPS     2 // not yet supported
#define RTMP_PROTOCOL_RTMPE     3
#define RTMP_PROTOCOL_RTMPTE    4 // not yet supported
#define RTMP_PROTOCOL_RTMFP     5 // not yet supported

char *str2lower(char *str, int len)
{
	char *res = (char *)malloc(len+1);
	char *p;

	for(p=res; p<res+len; p++, str++) {
		*p = tolower(*str);
	}

	*p = 0;

	return res;
}

int chr2hex(char c)
{
	if(c <= 57 && c >= 48)
        	return c-48;
        else if(c <= 102 && c >= 97)
                return c-97+10;
        
        return -1;
}

int hex2bin(char *str, char **hex)
{
	if(!str || !hex)
		return 0;

	int len = strlen(str);

	if(len % 2 != 0)
		return 0;

	int ret = len/2;

	*hex = (char *)malloc(ret);
	if((*hex)==0)
		return 0;

	char *hexptr = *hex;
	char *lwo = str2lower(str, len);
	char *lw = lwo;

	len /= 2;

	while(len) {
		int d1 = chr2hex(*lw); lw++;
		int d2 = chr2hex(*lw); lw++;

		if(d1<0 || d2<0) {
			free(*hex);
			free(lwo);
			*hex=NULL;
			return -1;
		}

		*hexptr = (unsigned char)(d1*16+d2);
		hexptr++;
		len--;
	}

	free(lwo);
	return ret;
}

int ParseUrl(char *url, int *protocol, char **host, unsigned int *port, char **playpath, char **app)
{
	assert(url != 0 && protocol != 0 && host != 0 && port != 0 && playpath != 0 && app != 0);

	Log(LOGDEBUG, "Parsing...");

	*protocol = 0; // default: RTMP

	// Old School Parsing
	char *lw = str2lower(url, 6);
	char *temp;

	// look for usual :// pattern
	char *p = strstr(url, "://");
	int len = (int)(p-url);
	if(p == 0) {
		Log(LOGWARNING, "RTMP URL: No :// in url!");
		free(lw);
		return 0;
	}

	if(len == 4 && strncmp(lw, "rtmp", 4)==0)
		*protocol = RTMP_PROTOCOL_RTMP;
	else if(len == 5 && strncmp(lw, "rtmpt", 5)==0)
		*protocol = RTMP_PROTOCOL_RTMPT;
	else if(len == 5 && strncmp(lw, "rtmps", 5)==0)
	        *protocol = RTMP_PROTOCOL_RTMPS;
	else if(len == 5 && strncmp(lw, "rtmpe", 5)==0)
	        *protocol = RTMP_PROTOCOL_RTMPE;
	else if(len == 5 && strncmp(lw, "rtmfp", 5)==0)
	        *protocol = RTMP_PROTOCOL_RTMFP;
	else if(len == 6 && strncmp(lw, "rtmpte", 6)==0)
	        *protocol = RTMP_PROTOCOL_RTMPTE;
	else {
		Log(LOGWARNING, "Unknown protocol!\n");
		goto parsehost;
	}

	Log(LOGDEBUG, "Parsed protocol: %d", *protocol);

parsehost:
	free(lw);

	// lets get the hostname
	p+=3;

	// check for sudden death
	if(*p==0) {
		Log(LOGWARNING, "No hostname in URL!");		
		return 0;
	}

	int iEnd   = strlen(p);
	int iCol   = iEnd+1; 
	int iQues  = iEnd+1;
	int iSlash = iEnd+1;

	if((temp=strstr(p, ":"))!=0)
		iCol = temp-p;
	if((temp=strstr(p, "?"))!=0)
	        iQues = temp-p;
	if((temp=strstr(p, "/"))!=0)
	        iSlash = temp-p;

	int min = iSlash < iEnd ? iSlash : iEnd+1;
	min = iQues   < min ? iQues   : min;

	int hostlen = iCol < min ? iCol : min;

	if(min < 256) {
		*host = (char *)malloc((hostlen+1)*sizeof(char));
		strncpy(*host, p, hostlen);
		(*host)[hostlen]=0;

		Log(LOGDEBUG, "Parsed host    : %s", *host);
	} else {
		Log(LOGWARNING, "Hostname exceeds 255 characters!");
	}

	p+=hostlen; iEnd-=hostlen;

	// get the port number if available
	if(*p == ':') {
		p++; iEnd--;

		int portlen = min-hostlen-1;
		if(portlen < 6) {
			char portstr[6];
			strncpy(portstr,p,portlen);
			portstr[portlen]=0;

			*port = atoi(portstr);
			if(*port == 0)
				*port = 1935;

			Log(LOGDEBUG, "Parsed port    : %d", *port);
		} else {
			Log(LOGWARNING, "Port number is longer than 5 characters!");
		}

		p+=portlen; iEnd-=portlen;
	}

	if(*p != '/') {
		Log(LOGWARNING, "No application or playpath in URL!");
		return 1;
	}
	p++; iEnd--;

	// parse application
	//
	// rtmp://host[:port]/app[/appinstance][/...]
	// application = app[/appinstance]
	int iSlash2 = iEnd+1; // 2nd slash
        int iSlash3 = iEnd+1; // 3rd slash

        if((temp=strstr(p, "/"))!=0)
        	iSlash2 = temp-p;
	
	if((temp=strstr(p, "?"))!=0)
	        iQues = temp-p;

	if(iSlash2 < iEnd)
		if((temp=strstr(p+iSlash2+1, "/"))!=0)
			iSlash3 = temp-p;

	//Log(LOGDEBUG, "p:%s, iEnd: %d\niSlash : %d\niSlash2: %d\niSlash3: %d", p, iEnd, iSlash, iSlash2, iSlash3);
	
	int applen = iEnd+1; // ondemand, pass all parameters as app
	int appnamelen = 8; // ondemand length

	if(iQues < iEnd && strstr(p, "slist=")) { // whatever it is, the '?' and slist= means we need to use everything as app and parse plapath from slist=
		appnamelen = iQues;
		applen = iEnd+1; // pass the parameters as well
	}
	else if(strncmp(p, "ondemand/", 9)==0) {
                // app = ondemand/foobar, only pass app=ondemand
                applen = 8;
        }
	else { // app!=ondemand, so app is app[/appinstance]
		appnamelen = iSlash2 < iEnd ? iSlash2 : iEnd;
        	if(iSlash3 < iEnd)
                	appnamelen = iSlash3;
	
		applen = appnamelen;
	}

	*app = (char *)malloc((applen+1)*sizeof(char));
	strncpy(*app, p, applen);
	(*app)[applen]=0;
	Log(LOGDEBUG, "Parsed app     : %s", *app);

	p += appnamelen; 
	iEnd -= appnamelen;

	if (*p == '/') {
		p += 1;
		iEnd -= 1;
	}

	*playpath = ParsePlaypath(p);

        return 1;
}

/*
 * Extracts playpath from RTMP URL. playpath is the file part of the
 * URL, i.e. the part that comes after rtmp://host:port/app/
 *
 * Returns the stream name in a format understood by FMS. The name is
 * the playpath part of the URL with formating depending on the stream
 * type:
 *
 * mp4 streams: prepend "mp4:"
 * mp3 streams: prepend "mp3:", remove extension
 * flv streams: remove extension
 */
char *ParsePlaypath(const char *playpath) {
	if (!playpath || !*playpath)
		return NULL;

	int addMP4 = 0;
	int addMP3 = 0;
	const char *temp;
	const char *ppstart = playpath;
	int pplen = strlen(playpath);

	if ((*ppstart == '?') &&
	    (temp=strstr(ppstart, "slist=")) != 0) {
		ppstart = temp+6;
		pplen = strlen(ppstart);

		temp = strchr(ppstart, '&');
		if (temp) {
			pplen = temp-ppstart;
		}
	}

	if (pplen >= 4) {
		const char *ext = &ppstart[pplen-4];
		if ((strcmp(ext, ".f4v") == 0) ||
		    (strcmp(ext, ".mp4") == 0)) {
			addMP4 = 1;
		// Only remove .flv from rtmp URL, not slist params
		} else if ((ppstart == playpath) &&
		    (strcmp(ext, ".flv") == 0)) {
			pplen -= 4;
		} else if (strcmp(ext, ".mp3") == 0) {
			addMP3 = 1;
			pplen -= 4;
		}
	}

	char *streamname = (char *)malloc((pplen+4+1)*sizeof(char));
	if (!streamname)
		return NULL;

	char *destptr = streamname;
	if (addMP4 && (strncmp(ppstart, "mp4:", 4) != 0)) {
		strcpy(destptr, "mp4:");
		destptr += 4;
	} else if (addMP3 && (strncmp(ppstart, "mp3:", 4) != 0)) {
		strcpy(destptr, "mp3:");
		destptr += 4;
	}

	strncpy(destptr, ppstart, pplen);
	destptr[pplen] = '\0';

	return streamname;
}
