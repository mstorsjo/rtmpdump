/*
 *  Copyright (C) 2008-2009 Andrej Stepanchuk
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

/* This file is #included in rtmp.c, it is not meant to be compiled alone */

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rc4.h>

#include "dh.h"

static const char GenuineFMSKey[] = {
  0x47, 0x65, 0x6e, 0x75, 0x69, 0x6e, 0x65, 0x20, 0x41, 0x64, 0x6f, 0x62,
    0x65, 0x20, 0x46, 0x6c,
  0x61, 0x73, 0x68, 0x20, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x20, 0x53, 0x65,
    0x72, 0x76, 0x65, 0x72,
  0x20, 0x30, 0x30, 0x31,	/* Genuine Adobe Flash Media Server 001 */

  0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8, 0x2e, 0x00, 0xd0, 0xd1,
  0x02, 0x9e, 0x7e, 0x57, 0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab,
    0x93, 0xb8, 0xe6, 0x36,
  0xcf, 0xeb, 0x31, 0xae
};				/* 68 */

static const char GenuineFPKey[] = {
  0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E, 0x65, 0x20, 0x41, 0x64, 0x6F, 0x62,
    0x65, 0x20, 0x46, 0x6C,
  0x61, 0x73, 0x68, 0x20, 0x50, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x20, 0x30,
    0x30, 0x31,			/* Genuine Adobe Flash Player 001 */
  0xF0, 0xEE,
  0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E,
    0x7E, 0x57, 0x6E, 0xEC,
  0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB,
    0x31, 0xAE
};				/* 62 */

static void InitRC4Encryption
  (uint8_t * secretKey,
   uint8_t * pubKeyIn,
   uint8_t * pubKeyOut, RC4_KEY ** rc4keyIn, RC4_KEY ** rc4keyOut)
{
  uint8_t digest[SHA256_DIGEST_LENGTH];
  unsigned int digestLen = 0;

  *rc4keyIn = malloc(sizeof(RC4_KEY));
  *rc4keyOut = malloc(sizeof(RC4_KEY));

  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx, secretKey, 128, EVP_sha256(), 0);
  HMAC_Update(&ctx, pubKeyIn, 128);
  HMAC_Final(&ctx, digest, &digestLen);
  HMAC_CTX_cleanup(&ctx);

  Log(LOGDEBUG, "RC4 Out Key: ");
  LogHex(LOGDEBUG, (char *) digest, 16);

  RC4_set_key(*rc4keyOut, 16, digest);

  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx, secretKey, 128, EVP_sha256(), 0);
  HMAC_Update(&ctx, pubKeyOut, 128);
  HMAC_Final(&ctx, digest, &digestLen);
  HMAC_CTX_cleanup(&ctx);

  Log(LOGDEBUG, "RC4 In Key: ");
  LogHex(LOGDEBUG, (char *) digest, 16);

  RC4_set_key(*rc4keyIn, 16, digest);
}

static unsigned int
GetDHOffset2(char *handshake, unsigned int len)
{
  unsigned int offset = 0;
  unsigned char *ptr = (unsigned char *) handshake + 768;

  assert(RTMP_SIG_SIZE <= len);

  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);

  unsigned int res = (offset % 632) + 8;

  if (res + 128 > 767)
    {
      Log(LOGERROR,
	  "%s: Couldn't calculate correct DH offset (got %d), exiting!\n",
	  __FUNCTION__, res);
      exit(1);
    }
  return res;
}

static unsigned int
GetDigestOffset2(char *handshake, unsigned int len)
{
  unsigned int offset = 0;
  unsigned char *ptr = (unsigned char *) handshake + 772;

  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);

  unsigned int res = (offset % 728) + 776;

  if (res + 32 > 1535)
    {
      Log(LOGERROR,
	  "%s: Couldn't calculate correct digest offset (got %d), exiting\n",
	  __FUNCTION__, res);
      exit(1);
    }
  return res;
}

static unsigned int
GetDHOffset1(char *handshake, unsigned int len)
{
  unsigned int offset = 0;
  unsigned char *ptr = (unsigned char *) handshake + 1532;

  assert(RTMP_SIG_SIZE <= len);

  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);

  unsigned int res = (offset % 632) + 772;

  if (res + 128 > 1531)
    {
      Log(LOGERROR, "%s: Couldn't calculate DH offset (got %d), exiting!\n",
	  __FUNCTION__, res);
      exit(1);
    }

  return res;
}

static unsigned int
GetDigestOffset1(char *handshake, unsigned int len)
{
  unsigned int offset = 0;
  unsigned char *ptr = (unsigned char *) handshake + 8;

  assert(12 <= len);

  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);

  unsigned int res = (offset % 728) + 12;

  if (res + 32 > 771)
    {
      Log(LOGDEBUG,
	  "%s: Couldn't calculate digest offset (got %d), exiting!\n",
	  __FUNCTION__, res);
      exit(1);
    }

  return res;
}

static void
HMACsha256(const char *message, size_t messageLen, const char *key,
	   size_t keylen, char *digest)
{
  unsigned int digestLen;

  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx, (unsigned char *) key, keylen, EVP_sha256(), NULL);
  HMAC_Update(&ctx, (unsigned char *) message, messageLen);
  HMAC_Final(&ctx, (unsigned char *) digest, &digestLen);
  HMAC_CTX_cleanup(&ctx);

  assert(digestLen == 32);
}

static void
CalculateDigest(unsigned int digestPos, char *handshakeMessage,
		const char *key, size_t keyLen, char *digest)
{
  const int messageLen = RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH;
  char message[messageLen];

  memcpy(message, handshakeMessage, digestPos);
  memcpy(message + digestPos,
	 &handshakeMessage[digestPos + SHA256_DIGEST_LENGTH],
	 messageLen - digestPos);

  HMACsha256(message, messageLen, key, keyLen, digest);
}

static bool
VerifyDigest(unsigned int digestPos, char *handshakeMessage, const char *key,
	     size_t keyLen)
{
  char calcDigest[SHA256_DIGEST_LENGTH];

  CalculateDigest(digestPos, handshakeMessage, key, keyLen, calcDigest);

  return memcmp(&handshakeMessage[digestPos], calcDigest,
		SHA256_DIGEST_LENGTH) == 0;
}

/* handshake
 *
 * Type		= [1 bytes] 0x06, 0x08 encrypted, 0x03 plain
 * -------------------------------------------------------------------- [1536 bytes]
 * Uptime	= [4 bytes] big endian unsigned number, uptime
 * Version 	= [4 bytes] each byte represents a version number, e.g. 9.0.124.0
 * ...
 *
 */

static bool
HandShake(RTMP * r, bool FP9HandShake)
{
  int i;
  int dhposClient = 0;
  int digestPosClient = 0;
  RC4_KEY *keyIn = 0;
  RC4_KEY *keyOut = 0;
  bool encrypted = r->Link.protocol == RTMP_PROTOCOL_RTMPE
    || r->Link.protocol == RTMP_PROTOCOL_RTMPTE;

  char clientbuf[RTMP_SIG_SIZE + 1], *clientsig=clientbuf+1;
  char serversig[RTMP_SIG_SIZE];
  char type;
  uint32_t uptime;

  if (encrypted || r->Link.SWFHash.av_len)
    FP9HandShake = true;
  else
    FP9HandShake = false;

  r->Link.rc4keyIn = r->Link.rc4keyOut = 0;

  if (encrypted)
    clientbuf[0] = 0x06;	/* 0x08 is RTMPE as well */
  else
    clientbuf[0] = 0x03;

  uptime = htonl(RTMP_GetTime());
  memcpy(clientsig, &uptime, 4);

  if (FP9HandShake)
    {
      /* set version to at least 9.0.115.0 */
      clientsig[4] = 9;
      clientsig[5] = 0;
      clientsig[6] = 124;
      clientsig[7] = 2;

      Log(LOGDEBUG, "%s: Client type: %02X\n", __FUNCTION__, clientbuf[0]);
    }
  else
    {
      memset(&clientsig[4], 0, 4);
    }

  /* generate random data */
#ifdef _DEBUG
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    clientsig[i] = 0;
#else
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    clientsig[i] = (char) (rand() % 256);
#endif

  /* set handshake digest */
  if (FP9HandShake)
    {
      if (encrypted)
	{
	  /* generate Diffie-Hellmann parameters */
	  r->Link.dh = DHInit(1024);
	  if (!r->Link.dh)
	    {
	      Log(LOGERROR, "%s: Couldn't initialize Diffie-Hellmann!",
		  __FUNCTION__);
	      return false;
	    }

	  dhposClient = GetDHOffset1(clientsig, RTMP_SIG_SIZE);
	  Log(LOGDEBUG, "%s: DH pubkey position: %d", __FUNCTION__, dhposClient);

	  if (!DHGenerateKey(r->Link.dh))
	    {
	      Log(LOGERROR, "%s: Couldn't generate Diffie-Hellmann public key!",
		  __FUNCTION__);
	      return false;
	    }

	  if (!DHGetPublicKey
	      (r->Link.dh, (uint8_t *) &clientsig[dhposClient], 128))
	    {
	      Log(LOGERROR, "%s: Couldn't write public key!", __FUNCTION__);
	      return false;
	    }
	}

      digestPosClient = GetDigestOffset1(clientsig, RTMP_SIG_SIZE);	/* reuse this value in verification */
      Log(LOGDEBUG, "%s: Client digest offset: %d", __FUNCTION__,
	  digestPosClient);

      CalculateDigest(digestPosClient, clientsig, GenuineFPKey, 30,
		      &clientsig[digestPosClient]);

      Log(LOGDEBUG, "%s: Initial client digest: ", __FUNCTION__);
      LogHex(LOGDEBUG, (char *) clientsig + digestPosClient,
	     SHA256_DIGEST_LENGTH);
    }

#ifdef _DEBUG
  Log(LOGDEBUG, "Clientsig: ");
  LogHex(LOGDEBUG, clientsig, RTMP_SIG_SIZE);
#endif

  if (!WriteN(r, clientbuf, RTMP_SIG_SIZE + 1))
    return false;

  if (ReadN(r, &type, 1) != 1)	/* 0x03 or 0x06 */
    return false;

  Log(LOGDEBUG, "%s: Type Answer   : %02X", __FUNCTION__, type);

  if (type != clientbuf[0])
    Log(LOGWARNING, "%s: Type mismatch: client sent %d, server answered %d",
	__FUNCTION__, clientbuf[0], type);

  if (ReadN(r, serversig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return false;

  /* decode server response */
  memcpy(&uptime, serversig, 4);
  uptime = ntohl(uptime);

  Log(LOGDEBUG, "%s: Server Uptime : %d", __FUNCTION__, uptime);
  Log(LOGDEBUG, "%s: FMS Version   : %d.%d.%d.%d", __FUNCTION__, serversig[4],
      serversig[5], serversig[6], serversig[7]);

#ifdef _DEBUG
  Log(LOGDEBUG, "Server signature:");
  LogHex(LOGDEBUG, serversig, RTMP_SIG_SIZE);
#endif

  if (FP9HandShake)
    {
      int dhposServer;

      /* we have to use this signature now to find the correct algorithms for getting the digest and DH positions */
      int digestPosServer = GetDigestOffset2(serversig, RTMP_SIG_SIZE);

      if (!VerifyDigest(digestPosServer, serversig, GenuineFMSKey, 36))
	{
	  Log(LOGWARNING, "Trying different position for server digest!\n");
	  digestPosServer = GetDigestOffset1(serversig, RTMP_SIG_SIZE);

	  if (!VerifyDigest(digestPosServer, serversig, GenuineFMSKey, 36))
	    {
	      Log(LOGERROR, "Couldn't verify the server digest\n");	/* continuing anyway will probably fail */
	      return false;
	    }
	  dhposServer = GetDHOffset1(serversig, RTMP_SIG_SIZE);
	}
      else
        {
	  dhposServer = GetDHOffset2(serversig, RTMP_SIG_SIZE);
        }

      Log(LOGDEBUG, "%s: Server DH public key offset: %d", __FUNCTION__,
	  dhposServer);

      /* generate SWFVerification token (SHA256 HMAC hash of decompressed SWF, key are the last 32 bytes of the server handshake) */
      if (r->Link.SWFHash.av_len)
	{
	  const char swfVerify[] = { 0x01, 0x01 };
          char *vend = r->Link.SWFVerificationResponse+sizeof(r->Link.SWFVerificationResponse);

	  memcpy(r->Link.SWFVerificationResponse, swfVerify, 2);
	  AMF_EncodeInt32(&r->Link.SWFVerificationResponse[2], vend, r->Link.SWFSize);
	  AMF_EncodeInt32(&r->Link.SWFVerificationResponse[6], vend, r->Link.SWFSize);
	  HMACsha256(r->Link.SWFHash.av_val, SHA256_DIGEST_LENGTH,
		     &serversig[RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH],
		     SHA256_DIGEST_LENGTH, &r->Link.SWFVerificationResponse[10]);
	}

      /* do Diffie-Hellmann Key exchange for encrypted RTMP */
      if (encrypted)
	{
	  /* compute secret key */
	  uint8_t secretKey[128] = { 0 };

	  int len =
	    DHComputeSharedSecretKey(r->Link.dh,
				     (uint8_t *) & serversig[dhposServer], 128,
				     secretKey);
	  if (len < 0)
	    {
	      Log(LOGDEBUG, "%s: Wrong secret key position!", __FUNCTION__);
	      return false;
	    }

	  Log(LOGDEBUG, "%s: Secret key: ", __FUNCTION__);
	  LogHex(LOGDEBUG, (char *) secretKey, 128);

	  InitRC4Encryption(secretKey,
			    (uint8_t *) & serversig[dhposServer],
			    (uint8_t *) & clientsig[dhposClient],
			    &keyIn, &keyOut);
	}


      /* calculate response now */
      char digestResp[SHA256_DIGEST_LENGTH];
      char *signatureResp = serversig+RTMP_SIG_SIZE-SHA256_DIGEST_LENGTH;

      HMACsha256(&serversig[digestPosServer], SHA256_DIGEST_LENGTH,
		 GenuineFPKey, sizeof(GenuineFPKey), digestResp);
      HMACsha256(serversig, RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH, digestResp,
		 SHA256_DIGEST_LENGTH, signatureResp);

      /* some info output */
      Log(LOGDEBUG,
	  "%s: Calculated digest key from secure key and server digest: ",
	  __FUNCTION__);
      LogHex(LOGDEBUG, digestResp, SHA256_DIGEST_LENGTH);

      Log(LOGDEBUG, "%s: Client signature calculated:", __FUNCTION__);
      LogHex(LOGDEBUG, signatureResp, SHA256_DIGEST_LENGTH);
    }
  else
    {
      uptime = htonl(RTMP_GetTime());
      memcpy(serversig+4, &uptime, 4);
    }

#ifdef _DEBUG
  Log(LOGDEBUG, "%s: Sending handshake response: ",
    __FUNCTION__);
  LogHex(LOGDEBUG, serversig, RTMP_SIG_SIZE);
#endif
  if (!WriteN(r, serversig, RTMP_SIG_SIZE))
    return false;

  /* 2nd part of handshake */
  if (ReadN(r, serversig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return false;

#ifdef _DEBUG
  Log(LOGDEBUG, "%s: 2nd handshake: ", __FUNCTION__);
  LogHex(LOGDEBUG, serversig, RTMP_SIG_SIZE);
#endif

  if (FP9HandShake)
    {
      char signature[SHA256_DIGEST_LENGTH];
      char digest[SHA256_DIGEST_LENGTH];

      if (serversig[4] == 0 && serversig[5] == 0 && serversig[6] == 0
	  && serversig[7] == 0)
	{
	  Log(LOGDEBUG,
	      "%s: Wait, did the server just refuse signed authentication?",
	      __FUNCTION__);
	}
      Log(LOGDEBUG, "%s: Server sent signature:", __FUNCTION__);
      LogHex(LOGDEBUG, &serversig[RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH],
	     SHA256_DIGEST_LENGTH);

      /* verify server response */
      HMACsha256(&clientsig[digestPosClient], SHA256_DIGEST_LENGTH,
		 GenuineFMSKey, sizeof(GenuineFMSKey), digest);
      HMACsha256(serversig, RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH, digest,
		 SHA256_DIGEST_LENGTH, signature);

      /* show some information */
      Log(LOGDEBUG, "%s: Digest key: ", __FUNCTION__);
      LogHex(LOGDEBUG, digest, SHA256_DIGEST_LENGTH);

      Log(LOGDEBUG, "%s: Signature calculated:", __FUNCTION__);
      LogHex(LOGDEBUG, signature, SHA256_DIGEST_LENGTH);
      if (memcmp
	  (signature, &serversig[RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH],
	   SHA256_DIGEST_LENGTH) != 0)
	{
	  Log(LOGWARNING, "%s: Server not genuine Adobe!", __FUNCTION__);
	  return false;
	}
      else
	{
	  Log(LOGDEBUG, "%s: Genuine Adobe Flash Media Server", __FUNCTION__);
	}

      if (encrypted)
	{
	  /* set keys for encryption from now on */
	  r->Link.rc4keyIn = keyIn;
	  r->Link.rc4keyOut = keyOut;

	  char buff[RTMP_SIG_SIZE];

	  /* update the keystreams */
	  if (r->Link.rc4keyIn)
	    {
	      RC4(r->Link.rc4keyIn, RTMP_SIG_SIZE, (uint8_t *) buff,
		  (uint8_t *) buff);
	    }

	  if (r->Link.rc4keyOut)
	    {
	      RC4(r->Link.rc4keyOut, RTMP_SIG_SIZE, (uint8_t *) buff,
		  (uint8_t *) buff);
	    }
	}
    }
  else
    {
      if (memcmp(serversig, clientsig, RTMP_SIG_SIZE) != 0)
	{
	  Log(LOGWARNING, "%s: client signature does not match!",
	      __FUNCTION__);
	}
    }

  Log(LOGDEBUG, "%s: Handshaking finished....", __FUNCTION__);
  return true;
}

static bool
SHandShake(RTMP * r)
{
  int i;
  int dhposClient = 0;
  int dhposServer = 0;
  int digestPosServer = 0;
  RC4_KEY *keyIn = 0;
  RC4_KEY *keyOut = 0;
  bool FP9HandShake = false;
  bool encrypted;

  char clientsig[RTMP_SIG_SIZE];
  char serverbuf[RTMP_SIG_SIZE + 1], *serversig = serverbuf+1;
  char type;
  uint32_t uptime;

  if (ReadN(r, &type, 1) != 1)	/* 0x03 or 0x06 */
    return false;

  Log(LOGDEBUG, "%s: Type Requested : %02X", __FUNCTION__, type);

  if (type == 3)
    {
      encrypted = false;
      r->Link.protocol = RTMP_PROTOCOL_RTMP;
    }
  else if (type == 6 || type == 8)
    {
      encrypted = true;
      FP9HandShake = true;
      r->Link.protocol = RTMP_PROTOCOL_RTMPE;
    }
  else
    {
      Log(LOGERROR, "%s: Unknown version %02x",
	  __FUNCTION__, type);
      return false;
    }

  serverbuf[0] = type;

  r->Link.rc4keyIn = r->Link.rc4keyOut = 0;

  uptime = htonl(RTMP_GetTime());
  memcpy(serversig, &uptime, 4);

  if (FP9HandShake)
    {
      /* Server version */
      serversig[4] = 3;
      serversig[5] = 5;
      serversig[6] = 1;
      serversig[7] = 1;
    }
  else
    {
      memset(&serversig[4], 0, 4);
    }

  /* generate random data */
#ifdef _DEBUG
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    serversig[i] = 0;
#else
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    serversig[i] = (char) (rand() % 256);
#endif

  /* set handshake digest */
  if (FP9HandShake)
    {
      if (encrypted)
	{
	  /* generate Diffie-Hellmann parameters */
	  r->Link.dh = DHInit(1024);
	  if (!r->Link.dh)
	    {
	      Log(LOGERROR, "%s: Couldn't initialize Diffie-Hellmann!",
		  __FUNCTION__);
	      return false;
	    }

	  dhposServer = GetDHOffset2(serversig, RTMP_SIG_SIZE);
	  Log(LOGDEBUG, "%s: DH pubkey position: %d", __FUNCTION__, dhposServer);

	  if (!DHGenerateKey(r->Link.dh))
	    {
	      Log(LOGERROR, "%s: Couldn't generate Diffie-Hellmann public key!",
		  __FUNCTION__);
	      return false;
	    }

	  if (!DHGetPublicKey
	      (r->Link.dh, (uint8_t *) &serversig[dhposServer], 128))
	    {
	      Log(LOGERROR, "%s: Couldn't write public key!", __FUNCTION__);
	      return false;
	    }
	}

      digestPosServer = GetDigestOffset2(serversig, RTMP_SIG_SIZE);	/* reuse this value in verification */
      Log(LOGDEBUG, "%s: Client digest offset: %d", __FUNCTION__,
	  digestPosServer);

      CalculateDigest(digestPosServer, serversig, GenuineFMSKey, 36,
		      &serversig[digestPosServer]);

      Log(LOGDEBUG, "%s: Initial server digest: ", __FUNCTION__);
      LogHex(LOGDEBUG, (char *) serversig + digestPosServer,
	     SHA256_DIGEST_LENGTH);
    }

#ifdef _DEBUG
  Log(LOGDEBUG, "Serversig: ");
  LogHex(LOGDEBUG, serversig, RTMP_SIG_SIZE);
#endif

  if (!WriteN(r, serverbuf, RTMP_SIG_SIZE + 1))
    return false;

  if (ReadN(r, clientsig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return false;

  /* decode client response */
  memcpy(&uptime, clientsig, 4);
  uptime = ntohl(uptime);

  Log(LOGDEBUG, "%s: Client Uptime : %d", __FUNCTION__, uptime);
  Log(LOGDEBUG, "%s: Player Version: %d.%d.%d.%d", __FUNCTION__, clientsig[4],
      clientsig[5], clientsig[6], clientsig[7]);

#ifdef _DEBUG
  Log(LOGDEBUG, "Client signature:");
  LogHex(LOGDEBUG, clientsig, RTMP_SIG_SIZE);
#endif

  if (FP9HandShake)
    {
      /* we have to use this signature now to find the correct algorithms for getting the digest and DH positions */
      int digestPosClient = GetDigestOffset1(clientsig, RTMP_SIG_SIZE);

      if (!VerifyDigest(digestPosClient, clientsig, GenuineFPKey, 30))
	{
	  Log(LOGWARNING, "Trying different position for client digest!\n");
	  digestPosClient = GetDigestOffset2(clientsig, RTMP_SIG_SIZE);

	  if (!VerifyDigest(digestPosClient, clientsig, GenuineFPKey, 30))
	    {
	      Log(LOGERROR, "Couldn't verify the client digest\n");	/* continuing anyway will probably fail */
	      return false;
	    }
	  dhposClient = GetDHOffset2(clientsig, RTMP_SIG_SIZE);
	}
      else
        {
	  dhposClient = GetDHOffset1(clientsig, RTMP_SIG_SIZE);
        }

      Log(LOGDEBUG, "%s: Client DH public key offset: %d", __FUNCTION__,
	  dhposClient);

      /* generate SWFVerification token (SHA256 HMAC hash of decompressed SWF, key are the last 32 bytes of the server handshake) */
      if (r->Link.SWFHash.av_len)
	{
	  const char swfVerify[] = { 0x01, 0x01 };
          char *vend = r->Link.SWFVerificationResponse+sizeof(r->Link.SWFVerificationResponse);

	  memcpy(r->Link.SWFVerificationResponse, swfVerify, 2);
	  AMF_EncodeInt32(&r->Link.SWFVerificationResponse[2], vend, r->Link.SWFSize);
	  AMF_EncodeInt32(&r->Link.SWFVerificationResponse[6], vend, r->Link.SWFSize);
	  HMACsha256(r->Link.SWFHash.av_val, SHA256_DIGEST_LENGTH,
		     &serversig[RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH],
		     SHA256_DIGEST_LENGTH, &r->Link.SWFVerificationResponse[10]);
	}

      /* do Diffie-Hellmann Key exchange for encrypted RTMP */
      if (encrypted)
	{
	  /* compute secret key */
	  uint8_t secretKey[128] = { 0 };

	  int len =
	    DHComputeSharedSecretKey(r->Link.dh,
				     (uint8_t *) &clientsig[dhposClient], 128,
				     secretKey);
	  if (len < 0)
	    {
	      Log(LOGDEBUG, "%s: Wrong secret key position!", __FUNCTION__);
	      return false;
	    }

	  Log(LOGDEBUG, "%s: Secret key: ", __FUNCTION__);
	  LogHex(LOGDEBUG, (char *) secretKey, 128);

	  InitRC4Encryption(secretKey,
			    (uint8_t *) &clientsig[dhposClient],
			    (uint8_t *) &serversig[dhposServer],
			    &keyIn, &keyOut);
	}


      /* calculate response now */
      char digestResp[SHA256_DIGEST_LENGTH];
      char *signatureResp = clientsig+RTMP_SIG_SIZE-SHA256_DIGEST_LENGTH;

      HMACsha256(&clientsig[digestPosClient], SHA256_DIGEST_LENGTH,
		 GenuineFMSKey, sizeof(GenuineFMSKey), digestResp);
      HMACsha256(clientsig, RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH, digestResp,
		 SHA256_DIGEST_LENGTH, signatureResp);

      /* some info output */
      Log(LOGDEBUG,
	  "%s: Calculated digest key from secure key and server digest: ",
	  __FUNCTION__);
      LogHex(LOGDEBUG, digestResp, SHA256_DIGEST_LENGTH);

      Log(LOGDEBUG, "%s: Server signature calculated:", __FUNCTION__);
      LogHex(LOGDEBUG, signatureResp, SHA256_DIGEST_LENGTH);
    }
  else
    {
      uptime = htonl(RTMP_GetTime());
      memcpy(clientsig+4, &uptime, 4);
    }

#ifdef _DEBUG
  Log(LOGDEBUG, "%s: Sending handshake response: ",
    __FUNCTION__);
  LogHex(LOGDEBUG, clientsig, RTMP_SIG_SIZE);
#endif
  if (!WriteN(r, clientsig, RTMP_SIG_SIZE))
    return false;

  /* 2nd part of handshake */
  if (ReadN(r, clientsig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return false;

#ifdef _DEBUG
  Log(LOGDEBUG, "%s: 2nd handshake: ", __FUNCTION__);
  LogHex(LOGDEBUG, clientsig, RTMP_SIG_SIZE);
#endif

  if (FP9HandShake)
    {
      char signature[SHA256_DIGEST_LENGTH];
      char digest[SHA256_DIGEST_LENGTH];

      Log(LOGDEBUG, "%s: Client sent signature:", __FUNCTION__);
      LogHex(LOGDEBUG, &clientsig[RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH],
	     SHA256_DIGEST_LENGTH);

      /* verify client response */
      HMACsha256(&serversig[digestPosServer], SHA256_DIGEST_LENGTH,
		 GenuineFPKey, sizeof(GenuineFPKey), digest);
      HMACsha256(clientsig, RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH, digest,
		 SHA256_DIGEST_LENGTH, signature);

      /* show some information */
      Log(LOGDEBUG, "%s: Digest key: ", __FUNCTION__);
      LogHex(LOGDEBUG, digest, SHA256_DIGEST_LENGTH);

      Log(LOGDEBUG, "%s: Signature calculated:", __FUNCTION__);
      LogHex(LOGDEBUG, signature, SHA256_DIGEST_LENGTH);
      if (memcmp
	  (signature, &clientsig[RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH],
	   SHA256_DIGEST_LENGTH) != 0)
	{
	  Log(LOGWARNING, "%s: Client not genuine Adobe!", __FUNCTION__);
	  return false;
	}
      else
	{
	  Log(LOGDEBUG, "%s: Genuine Adobe Flash Player", __FUNCTION__);
	}

      if (encrypted)
	{
	  /* set keys for encryption from now on */
	  r->Link.rc4keyIn = keyIn;
	  r->Link.rc4keyOut = keyOut;

	  char buff[RTMP_SIG_SIZE];

	  /* update the keystreams */
	  if (r->Link.rc4keyIn)
	    {
	      RC4(r->Link.rc4keyIn, RTMP_SIG_SIZE, (uint8_t *) buff,
		  (uint8_t *) buff);
	    }

	  if (r->Link.rc4keyOut)
	    {
	      RC4(r->Link.rc4keyOut, RTMP_SIG_SIZE, (uint8_t *) buff,
		  (uint8_t *) buff);
	    }
	}
    }
  else
    {
      if (memcmp(serversig, clientsig, RTMP_SIG_SIZE) != 0)
	{
	  Log(LOGWARNING, "%s: client signature does not match!",
	      __FUNCTION__);
	}
    }

  Log(LOGDEBUG, "%s: Handshaking finished....", __FUNCTION__);
  return true;
}
