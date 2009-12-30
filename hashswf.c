/*
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

#include <stdio.h>
#include <string.h>

#ifdef WIN32
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

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
  int hlen, flen;
  int s = -1, rc, i, ret = 0;
  FILE *sf = NULL;
  struct sockaddr_in sa;
  char buf[4096];

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
  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s < 0)
    return -1;
  i = sprintf(buf, "GET %s HTTP/1.0\r\nUser-Agent: %s\r\nHost: %s\r\n", path, AGENT, host);
  if (in->date[0])
    i += sprintf(buf+i, "If-Modified-Since: %s\r\n", in->date);
  i += sprintf(buf+i, "\r\n");

  if (connect(s, (struct sockaddr *)&sa, sizeof(struct sockaddr)) < 0)
    {
      ret = -1;
      goto leave;
    }
  write(s, buf, i);
  sf = fdopen(s, "rb");

  if (!fgets(buf, sizeof(buf), sf))
    {
      ret = -1;
      goto leave;
    }
  if (strncmp(buf, "HTTP/1", 6))
    {
      ret = -1;
      goto leave;
    }

  p1 = strchr(buf, ' ');
  rc = atoi(p1+1);

  /* not modified */
  if (rc == 304)
    goto leave;

  while(fgets(buf, sizeof(buf), sf))
    {
      if (!strncasecmp(buf, "Content-Length: ", sizeof("Content-Length: ")-1))
        {
          flen = atoi(buf+sizeof("Content-Length: ")-1);
        }
      else if (!strncasecmp(buf, "Last-Modified: ", sizeof("Last-Modified: ")-1))
        {
          p1 = buf+sizeof("Last-Modified: ")-1;
          p2 = strchr(p1, '\r');
          *p2 = '\0';
          strcpy(in->date, p1);
        }
      else if (buf[0] == '\r')
        break;
    }

  hlen = sizeof(buf);
  while ((i=fread(buf, 1, hlen, sf))>0)
    {
      swfcrunch(buf, 1, i, in);
      flen -= i;
      if (flen < 1)
        break;
      if (hlen > flen)
        hlen = flen;
    }

leave:
  if (sf)
    fclose(sf);
  else if (s >= 0)
    close(s);
  return ret;
}

#define HEX2BIN(a)      (((a)&0x40)?((a)&0xf)+9:((a)&0xf))

int
RTMP_HashSWF(const char *url, unsigned int *size, unsigned char *hash, int ask)
{
  FILE *f = NULL;
  char *path, *home, date[64];
  long pos = 0;
  int i, got = 0, ret = 0;
  unsigned int hlen;
  struct info in = {0};
  z_stream zs = {0};
  HMAC_CTX ctx;

  date[0] = '\0';
  home = getenv("HOME");
  if (!home)
    home = ".";

  path=malloc(strlen(home)+sizeof("/.swfinfo"));
  strcpy(path, home);
  strcat(path, "/.swfinfo");

  f = fopen(path, "r+");
  if (f)
    {
      char buf[4096], *file;

      file = strrchr(url, '/');

      while (fgets(buf, sizeof(buf), f))
        {
          char *r1;

          got = 0;

          if (strncmp(buf, "url: ", 5))
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
              else if (!strncmp(buf, "url: ", 5))
                break;
            }
          break;
        }
    }

  if (got && !ask)
    return 0;

  in.first = 1;
  in.date = date;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx, "Genuine Adobe Flash Player 001", 30, EVP_sha256(), NULL);
  inflateInit(&zs);
  in.ctx = &ctx;
  in.zs = &zs;

  ret = http_get(url, &in);

  inflateEnd(&zs);

  if (!ret && !in.first)
    {
      HMAC_Final(&ctx, (unsigned char *)hash, &hlen);
      if (got && pos)
        fseek(f, pos, SEEK_SET);
      else
        {
          char *q;
          if (!f)
            f = fopen(path, "w");
          if (!f)
            return -1;
          fseek(f, 0, SEEK_END);
          q = strchr(url, '?');
          if (q)
            i = q - url;
          else
            i = strlen(url);

          fprintf(f, "url: %.*s\n", i, url);
        }
      fprintf(f, "date: %s\n", date);
      fprintf(f, "size: %08x\n", in.size);
      fprintf(f, "hash: ");
      for (i=0; i<SHA256_DIGEST_LENGTH; i++)
        fprintf(f, "%02x", hash[i]);
      fprintf(f, "\n");
      *size = in.size;
    }
  HMAC_CTX_cleanup(&ctx);
  fclose(f);
  return ret;
}
