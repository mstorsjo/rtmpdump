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

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <curl/curl.h>
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

static size_t
hdrcrunch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  struct info *i = stream;
  char *p = ptr;
  size_t len = size * nmemb;

  if (!strncmp(p, "Last-Modified: ", 15))
    {
      int l = len-15;
      strncpy(i->date, p+15, l);
      if (i->date[l-1] == '\n')
        l--;
      if (i->date[l-1] == '\r')
        l--;
      i->date[l] = '\0';
    }
  return len;
}

#define HEX2BIN(a)      (((a)&0x40)?((a)&0xf)+9:((a)&0xf))

int
SWFVerify(const char *url, unsigned int *size, unsigned char *hash)
{
  FILE *f = NULL;
  char *path, *home, date[64];
  long pos = 0;
  int i, got = 0, ret = 0;
  unsigned int hlen;
  CURL *c;
  char csbuf[96];
  struct curl_slist cs = {csbuf};
  struct info in;
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
          buf[strlen(buf)-1] = '\0';
          if (strcmp(r1, file))
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
                  strncpy(date, buf, sizeof(date));
                  got++;
                }
              else if (!strncmp(buf, "url: ", 5))
                break;
            }
          break;
        }
    }

  in.first = 1;
  in.date = date;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx, "Genuine Adobe Flash Player 001", 30, EVP_sha256(), NULL);
  inflateInit(&zs);
  in.ctx = &ctx;
  in.zs = &zs;

  c = curl_easy_init();
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, swfcrunch);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &in);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, hdrcrunch);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, &in);
  curl_easy_setopt(c, CURLOPT_URL, url);
  if (date[0])
    {
      sprintf(csbuf, "If-Modified-Since: %s", date);
      curl_easy_setopt(c, CURLOPT_HTTPHEADER, &cs);
    }
  ret = curl_easy_perform(c);
  curl_easy_cleanup(c);

  inflateEnd(&zs);

  if (!ret && !in.first)
    {
      HMAC_Final(&ctx, (unsigned char *)hash, &hlen);
      if (got && pos)
        fseek(f, pos, SEEK_SET);
      else
        {
          if (!f)
            f = fopen(path, "w");
          fseek(f, 0, SEEK_END);
          fprintf(f, "url: %s\n", url);
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
