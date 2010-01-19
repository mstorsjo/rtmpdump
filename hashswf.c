/*
 *  Copyright (C) 2009-2010 Howard Chu
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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "rtmp.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <zlib.h>

struct info {
  HMAC_CTX *ctx;
  z_stream *zs;
  char *date;
  int first;
  int zlib;
  int size;
};

#define CHUNK	16384

static size_t
swfcrunch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  struct info *i = stream;
  char *p = ptr;
  size_t len = size * nmemb;

  if (i->first)
    {
      i->first = 0;
      /* compressed? */
      if (!strncmp(p, "CWS", 3))
        {
          *p = 'F';
          i->zlib = 1;
        }
      HMAC_Update(i->ctx, (unsigned char *)p, 8);
      p += 8;
      len -= 8;
      i->size = 8;
    }

  if (i->zlib)
    {
      unsigned char out[CHUNK];
      i->zs->next_in = (unsigned char *)p;
      i->zs->avail_in = len;
      do
        {
          i->zs->avail_out = CHUNK;
          i->zs->next_out = out;
          inflate(i->zs, Z_NO_FLUSH);
          len = CHUNK - i->zs->avail_out;
          i->size += len;
          HMAC_Update(i->ctx, out, len);
        } while (i->zs->avail_out == 0);
    }
  else
    {
      i->size += len;
      HMAC_Update(i->ctx, (unsigned char *)p, len);
    }
  return size * nmemb;
}

#define	AGENT	"Mozilla/5.0"

static int
http_get(const char *url, struct info *in)
{
  char *host, *path;
  char *p1, *p2;
  char hbuf[256];
  int port = 80;
  int ssl = 0;
  int hlen, flen = 0;
  int rc, i, ret = 0;
  struct sockaddr_in sa;
  RTMPSockBuf sb;

  memset(&sa, 0, sizeof(struct sockaddr_in));
  sa.sin_family = AF_INET;

  /* we only handle http here */
  if (strncasecmp(url, "http", 4))
    return -1;

  if (url[4] == 's')
    {
      ssl = 1;
      port = 443;
    }

  p1 = strchr(url+4, ':');
  if (!p1 || strncmp(p1, "://", 3))
    return -1;

  host = p1+3;
  path = strchr(host, '/');
  hlen = path - host;
  strncpy(hbuf, host, hlen);
  hbuf[hlen] = '\0';
  host = hbuf;
  p1 = strrchr(host, ':');
  if (p1)
    {
      *p1++ = '\0';
      port = atoi(p1);
    }

  sa.sin_addr.s_addr = inet_addr(host);
  if (sa.sin_addr.s_addr == INADDR_NONE)
    {
      struct hostent *hp = gethostbyname(host);
      if (!hp || !hp->h_addr)
        return -1;
      sa.sin_addr = *(struct in_addr *)hp->h_addr;
    }
  sa.sin_port = htons(port);
  sb.sb_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sb.sb_socket < 0)
    return -1;
  i = sprintf(sb.sb_buf, "GET %s HTTP/1.0\r\nUser-Agent: %s\r\nHost: %s\r\nReferrer: %.*s\r\n",
    path, AGENT, host, path-url+1, url);
  if (in->date[0])
    i += sprintf(sb.sb_buf+i, "If-Modified-Since: %s\r\n", in->date);
  i += sprintf(sb.sb_buf+i, "\r\n");

  if (connect(sb.sb_socket, (struct sockaddr *)&sa, sizeof(struct sockaddr)) < 0)
    {
      ret = -1;
      goto leave;
    }
  send(sb.sb_socket, sb.sb_buf, i, 0);

  // set timeout
#define HTTP_TIMEOUT	5
  SET_RCVTIMEO(tv, HTTP_TIMEOUT);
  if (setsockopt
    (sb.sb_socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof(tv)))
    {
      Log(LOGERROR, "%s, Setting socket timeout to %ds failed!",
          __FUNCTION__, HTTP_TIMEOUT);
    }

  sb.sb_size = 0;
  sb.sb_timedout = false;
  if (RTMPSockBuf_Fill(&sb) < 1)
    {
      ret = -1;
      goto leave;
    }
  if (strncmp(sb.sb_buf, "HTTP/1", 6))
    {
      ret = -1;
      goto leave;
    }

  p1 = strchr(sb.sb_buf, ' ');
  rc = atoi(p1+1);

  /* not modified */
  if (rc == 304)
    goto leave;

  p1 = memchr(sb.sb_buf, '\n', sb.sb_size);
  if (!p1)
    {
      ret = -1;
      goto leave;
    }
  sb.sb_start = p1+1;
  sb.sb_size -= sb.sb_start - sb.sb_buf;

  while((p2=memchr(sb.sb_start, '\r', sb.sb_size)))
    {
      if (*sb.sb_start == '\r')
        {
          sb.sb_start += 2;
          sb.sb_size -= 2;
          break;
        }
      else if (!strncasecmp(sb.sb_start, "Content-Length: ", sizeof("Content-Length: ")-1))
        {
          flen = atoi(sb.sb_start+sizeof("Content-Length: ")-1);
        }
      else if (!strncasecmp(sb.sb_start, "Last-Modified: ", sizeof("Last-Modified: ")-1))
        {
          *p2 = '\0';
          strcpy(in->date, sb.sb_start+sizeof("Last-Modified: ")-1);
        }
      p2 += 2;
      sb.sb_size -= p2-sb.sb_start;
      sb.sb_start = p2;
      if (sb.sb_size < 1)
        {
          if (RTMPSockBuf_Fill(&sb) < 1)
            {
              ret = -1;
              goto leave;
            }
        }
    }

  while (flen > 0 && (sb.sb_size > 0 || RTMPSockBuf_Fill(&sb) > 0))
    {
      swfcrunch(sb.sb_start, 1, sb.sb_size, in);
      flen -= sb.sb_size;
      sb.sb_size = 0;
    }

leave:
  closesocket(sb.sb_socket);
  return ret;
}

static const char *monthtab[12] = {"Jan", "Feb", "Mar",
				"Apr", "May", "Jun",
				"Jul", "Aug", "Sep",
				"Oct", "Nov", "Dec"};
static const char *days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

/* Parse an HTTP datestamp into Unix time */
static time_t
make_unix_time(char *s)
{
    struct tm       time;
    int             i, ysub = 1900, fmt = 0;
    char           *month;
    char           *n;
    time_t res;

    if (s[3] != ' ')
    {
	fmt = 1;
	if (s[3] != ',')
	    ysub = 0;
    }
    for (n = s; *n; ++n)
	if (*n == '-' || *n == ':')
	    *n = ' ';

    time.tm_mon = 0;
    n = strchr(s, ' ');
    if (fmt)
    {
	/* Day, DD-MMM-YYYY HH:MM:SS GMT */
	time.tm_mday = strtol(n+1, &n, 0);
	month = n+1;
	n = strchr(month, ' ');
	time.tm_year = strtol(n+1, &n, 0);
	time.tm_hour = strtol(n+1, &n, 0);
	time.tm_min = strtol(n+1, &n, 0);
	time.tm_sec = strtol(n+1, NULL, 0);
    } else
    {
	/* Unix ctime() format. Does not conform to HTTP spec. */
	/* Day MMM DD HH:MM:SS YYYY */
	month = n+1;
	n = strchr(month, ' ');
	while (isspace(*n)) n++;
	time.tm_mday = strtol(n, &n, 0);
	time.tm_hour = strtol(n+1, &n, 0);
	time.tm_min = strtol(n+1, &n, 0);
	time.tm_sec = strtol(n+1, &n, 0);
	time.tm_year = strtol(n+1, NULL, 0);
    }
    if (time.tm_year > 100)
	time.tm_year -= ysub;

    for (i = 0; i < 12; i++)
	if (!strncasecmp(month, monthtab[i], 3))
	{
	    time.tm_mon = i;
	    break;
	}
    time.tm_isdst = 0;		/* daylight saving is never in effect in GMT */
    res = mktime(&time);
    /* Unfortunately, mktime() assumes the input is in local time,
     * not GMT, so we have to correct it here.
     */
    if (res != -1)
	res += timezone;
    return res;
}

/* Convert a Unix time to a network time string
 * Weekday, DD-MMM-YYYY HH:MM:SS GMT
 */
void strtime(time_t *t, char *s)
{
    struct tm *tm;

    tm = gmtime((time_t *)t);
    sprintf(s, "%s, %02d %s %d %02d:%02d:%02d GMT",
	days[tm->tm_wday], tm->tm_mday, monthtab[tm->tm_mon],
	tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);
}

#define HEX2BIN(a)      (((a)&0x40)?((a)&0xf)+9:((a)&0xf))

int
RTMP_HashSWF(const char *url, unsigned int *size, unsigned char *hash, int age)
{
  FILE *f = NULL;
  char *path, *home, date[64], cctim[64];
  long pos = 0;
  time_t ctim = -1, cnow;
  int i, got = 0, ret = 0;
  unsigned int hlen;
  struct info in = {0};
  z_stream zs = {0};
  HMAC_CTX ctx;

  date[0] = '\0';
  home = getenv("HOME");
  if (!home)
    home = ".";

  /* SWF hash info is cached in a fixed-format file.
   * url: <url of SWF file>
   * ctim: HTTP datestamp of when we last checked it.
   * date: HTTP datestamp of the SWF's last modification.
   * size: SWF size in hex
   * hash: SWF hash in hex
   *
   * These fields must be present in this order. All fields
   * besides URL are fixed size.
   */
  path=malloc(strlen(home)+sizeof("/.swfinfo"));
  strcpy(path, home);
  strcat(path, "/.swfinfo");

  f = fopen(path, "r+");
  while (f)
    {
      char buf[4096], *file, *p;

      file = strchr(url, '/');
      if (!file)
        break;
      file += 2;
      file = strchr(file, '/');
      if (!file)
        break;
      file++;
      hlen = file - url;
      p = strrchr(file, '/');
      if (p)
        file = p;
      else
        file--;

      while (fgets(buf, sizeof(buf), f))
        {
          char *r1;

          got = 0;

          if (strncmp(buf, "url: ", 5))
            continue;
          if (strncmp(buf+5, url, hlen))
            continue;
          r1 = strrchr(buf, '/');
          i = strlen(r1);
          r1[--i] = '\0';
          if (strncmp(r1, file, i))
            continue;
          pos = ftell(f);
          while (got < 3 && fgets(buf, sizeof(buf), f))
            {
              if (!strncmp(buf, "size: ", 6))
                {
                  *size = strtol(buf+6, NULL, 16);
                  got++;
                }
              else if (!strncmp(buf, "hash: ", 6))
                {
                  unsigned char *ptr = hash, *in = (unsigned char *)buf+6;
                  int l = strlen((char *)in)-1;
                  for (i=0; i<l; i+=2)
                    *ptr++ = (HEX2BIN(in[i]) << 4) | HEX2BIN(in[i+1]);
                  got++;
                }
              else if (!strncmp(buf, "date: ", 6))
                {
                  buf[strlen(buf)-1] = '\0';
                  strncpy(date, buf+6, sizeof(date));
                  got++;
                }
              else if (!strncmp(buf, "ctim: ", 6))
                {
                  buf[strlen(buf)-1] = '\0';
		  ctim = make_unix_time(buf+6);
                  got++;
                }
              else if (!strncmp(buf, "url: ", 5))
                break;
            }
          break;
        }
      break;
    }

  cnow = time(NULL);
  /* If we got a cache time, see if it's young enough to use directly */
  if (age && ctim > 0)
    {
      ctim = cnow - ctim;
      ctim /= 3600 * 24; /* seconds to days */
      if (ctim < age)	/* ok, it's new enough */
        goto out;
    }

  in.first = 1;
  in.date = date;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx, "Genuine Adobe Flash Player 001", 30, EVP_sha256(), NULL);
  inflateInit(&zs);
  in.ctx = &ctx;
  in.zs = &zs;

  ret = http_get(url, &in);

  inflateEnd(&zs);

  if (ret)
    {
      Log(LOGERROR, "%s: couldn't contact swfurl %s",
        __FUNCTION__, url);
    }
  else
    {
      if (got && pos)
        fseek(f, pos, SEEK_SET);
      else
        {
          char *q;
          if (!f)
            f = fopen(path, "w");
          if (!f)
            {
              int err = errno;
              Log(LOGERROR, "%s: couldn't open %s for writing, errno %d (%s)",
                __FUNCTION__, path, err, strerror(err));
              ret = -1;
              goto out;
            }
          fseek(f, 0, SEEK_END);
          q = strchr(url, '?');
          if (q)
            i = q - url;
          else
            i = strlen(url);

          fprintf(f, "url: %.*s\n", i, url);
        }
      strtime(&cnow, cctim);
      fprintf(f, "ctim: %s\n", cctim);

      if (!in.first)
        {
          HMAC_Final(&ctx, (unsigned char *)hash, &hlen);
          *size = in.size;

          fprintf(f, "date: %s\n", date);
          fprintf(f, "size: %08x\n", in.size);
          fprintf(f, "hash: ");
          for (i=0; i<SHA256_DIGEST_LENGTH; i++)
            fprintf(f, "%02x", hash[i]);
          fprintf(f, "\n");
        }
    }
  HMAC_CTX_cleanup(&ctx);
out:
  free(path);
  if (f)
    fclose(f);
  return ret;
}
