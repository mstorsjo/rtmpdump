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

#include <stdlib.h>
#include <string.h>

#include <assert.h>

#ifdef WIN32
#include <winsock.h>
#define close(x)        closesocket(x)
#else
#include <sys/times.h>
#endif

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rc4.h>

#include "rtmp.h"
#include "AMFObject.h"
#include "log.h"
#include "bytes.h"

#include "dh.h"

#define RTMP_SIG_SIZE 1536
#define RTMP_LARGE_HEADER_SIZE 12

#define RTMP_BUFFER_CACHE_SIZE (16*1024) // needs to fit largest number of bytes recv() may return

using namespace RTMP_LIB;
using namespace std;

const char GenuineFMSKey[] = 
{
        0x47, 0x65, 0x6e, 0x75, 0x69, 0x6e, 0x65, 0x20, 0x41, 0x64, 0x6f, 0x62, 0x65, 0x20, 0x46, 0x6c,
        0x61, 0x73, 0x68, 0x20, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
        0x20, 0x30, 0x30, 0x31, // Genuine Adobe Flash Media Server 001 

        0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8, 0x2e, 0x00, 0xd0, 0xd1,
        0x02, 0x9e, 0x7e, 0x57, 0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab, 0x93, 0xb8, 0xe6, 0x36,
        0xcf, 0xeb, 0x31, 0xae 
}; // 68

char GenuineFPKey[] =
{
        0x47,0x65,0x6E,0x75,0x69,0x6E,0x65,0x20,0x41,0x64,0x6F,0x62,0x65,0x20,0x46,0x6C,
        0x61,0x73,0x68,0x20,0x50,0x6C,0x61,0x79,0x65,0x72,0x20,0x30,0x30,0x31,0xF0,0xEE,
        0xC2,0x4A,0x80,0x68,0xBE,0xE8,0x2E,0x00,0xD0,0xD1,0x02,0x9E,0x7E,0x57,0x6E,0xEC,
        0x5D,0x2D,0x29,0x80,0x6F,0xAB,0x93,0xB8,0xE6,0x36,0xCF,0xEB,0x31,0xAE
}; // 62

void InitRC4Encryption
(
        uint8_t *secretKey, 
        uint8_t *pubKeyIn, 
        uint8_t *pubKeyOut,
        RC4_KEY **rc4keyIn,
        RC4_KEY **rc4keyOut
)
{
        uint8_t digest[SHA256_DIGEST_LENGTH];
        unsigned int digestLen = 0;

	*rc4keyIn = new RC4_KEY;
	*rc4keyOut = new RC4_KEY;

        HMAC_CTX ctx;
        HMAC_CTX_init(&ctx);
        HMAC_Init_ex(&ctx, secretKey, 128, EVP_sha256(), 0);
        HMAC_Update(&ctx, pubKeyIn, 128);
        HMAC_Final(&ctx, digest, &digestLen);
        HMAC_CTX_cleanup(&ctx);

	Log(LOGDEBUG, "RC4 Out Key: ");
	LogHex(LOGDEBUG, (char*)digest, 16);

        RC4_set_key(*rc4keyOut, 16, digest);

        HMAC_CTX_init(&ctx);
        HMAC_Init_ex(&ctx, secretKey, 128, EVP_sha256(), 0);
        HMAC_Update(&ctx, pubKeyOut, 128);
        HMAC_Final(&ctx, digest, &digestLen);
        HMAC_CTX_cleanup(&ctx);

	Log(LOGDEBUG, "RC4 In Key: ");
	LogHex(LOGDEBUG, (char*)digest, 16);
        
	RC4_set_key(*rc4keyIn, 16, digest);
}
/*
void RC4Encrypt(char *src, char *dst, size_t len)
{
	if(Link.rc4keyOut) {
		RC4(Link.rc4keyOut, len, (uint8_t*)src, (uint8_t*)dst);
	}
}

void RC4Decrypt(char *src, char *dst, size_t len)
{
	if(Link.rc4keyIn) {
		RC4(Link.rc4keyIn, len, (uint8_t*)src, (uint8_t*)dst);
	}
}
*/

unsigned int GetDHOffset2(char *handshake, unsigned int len)
{
        unsigned int offset = 0;
        unsigned char *ptr = (unsigned char *)handshake + 768;

        assert(RTMP_SIG_SIZE <= len);

        offset += (*ptr); ptr++;
        offset += (*ptr); ptr++;
        offset += (*ptr); ptr++;
        offset += (*ptr);

        unsigned int res = (offset % 632) + 8;

	if(res + 128 > 767) {
		Log(LOGERROR, "%s: Couldn't calculate correct DH offset (got %d), exiting!\n", __FUNCTION__, res);	
		exit(1);
	}
	return res;
}

unsigned int GetDigestOffset2(char *handshake, unsigned int len)
{
        unsigned int offset = 0;
        unsigned char *ptr = (unsigned char *)handshake + 772;

        //assert(12 <= len);

        offset += (*ptr); ptr++;
        offset += (*ptr); ptr++;
        offset += (*ptr); ptr++;
        offset += (*ptr);

        unsigned int res = (offset % 728) + 776;

	if(res+32 > 1535) {
		Log(LOGERROR, "%s: Couldn't calculate correct digest offset (got %d), exiting\n", __FUNCTION__, res);
		exit(1);
	}
	return res;
}

unsigned int GetDHOffset1(char *handshake, unsigned int len)
{
        unsigned int offset = 0;
        unsigned char *ptr = (unsigned char *)handshake + 1532;

        assert(RTMP_SIG_SIZE <= len);

        offset += (*ptr); ptr++;
        offset += (*ptr); ptr++;
        offset += (*ptr); ptr++;
        offset += (*ptr);

        unsigned int res = (offset % 632) + 772;

	if(res+128 > 1531) {
		Log(LOGERROR, "%s: Couldn't calculate DH offset (got %d), exiting!\n", __FUNCTION__, res);
		exit(1);
	}

	return res;
}

unsigned int GetDigestOffset1(char *handshake, unsigned int len)
{
        unsigned int offset = 0;
        unsigned char *ptr = (unsigned char *)handshake + 8;

        assert(12 <= len);

        offset += (*ptr); ptr++;
        offset += (*ptr); ptr++;
        offset += (*ptr); ptr++;
        offset += (*ptr);

        unsigned int res = (offset % 728) + 12;

	if(res+32 > 771) {
		Log(LOGDEBUG, "%s: Couldn't calculate digest offset (got %d), exiting!\n", __FUNCTION__, res);
		exit(1);
	}

	return res;
}

void HMACsha256(const char *message, size_t messageLen, const char *key, size_t keylen, char *digest)
{
	unsigned int digestLen;

	HMAC_CTX ctx;
        HMAC_CTX_init(&ctx);
        HMAC_Init_ex(&ctx, (unsigned char*)key, keylen, EVP_sha256(), NULL);
        HMAC_Update(&ctx, (unsigned char *)message, messageLen);
        HMAC_Final(&ctx, (unsigned char *)digest, &digestLen);
        HMAC_CTX_cleanup(&ctx);	

	assert(digestLen == 32);
}

void CalculateDigest(unsigned int digestPos, char *handshakeMessage, const char *key, size_t keyLen, char *digest)
{
	const int messageLen = RTMP_SIG_SIZE - SHA256_DIGEST_LENGTH;
        char message[messageLen];

        memcpy(message, handshakeMessage, digestPos);
        memcpy(message+digestPos, &handshakeMessage[digestPos+SHA256_DIGEST_LENGTH], messageLen-digestPos);

        HMACsha256(message, messageLen, key, keyLen, digest);
}

bool VerifyDigest(unsigned int digestPos, char *handshakeMessage, const char *key, size_t keyLen)
{
	char calcDigest[SHA256_DIGEST_LENGTH];

	CalculateDigest(digestPos, handshakeMessage, key, keyLen, calcDigest);

	return memcmp(&handshakeMessage[digestPos], calcDigest, SHA256_DIGEST_LENGTH)==0;
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

bool CRTMP::HandShake(bool FP9HandShake)
{
	bool encrypted = Link.protocol == RTMP_PROTOCOL_RTMPE || Link.protocol == RTMP_PROTOCOL_RTMPTE;

	if ( encrypted || Link.SWFHash )
		FP9HandShake = true;
	else
		FP9HandShake = false;

	char clientsig[RTMP_SIG_SIZE+1];
	char serversig[RTMP_SIG_SIZE];

	memset(clientsig, 0, RTMP_SIG_SIZE+1);

	Link.rc4keyIn = Link.rc4keyOut = 0;

	if(encrypted)
		clientsig[0] = 0x06; // 0x08 is RTMPE as well
	else
		clientsig[0] = 0x03;

#if 0
	uint32_t uptime = htonl(GetTime());
	memcpy(clientsig + 1, &uptime, 4);
#else
	clientsig[1] = 0;
	clientsig[2] = 0;
	clientsig[3] = 0;
	clientsig[4] = 0;
#endif

	if(FP9HandShake) {
		//* TODO RTMPE ;), its just RC4 with diffie-hellman
		// set version to at least 9.0.115.0
		clientsig[5] = 9;
		clientsig[6] = 0;
		clientsig[7] = 124;
		clientsig[8] = 2;

		//Log(LOGDEBUG, "Client type: %02X\n", clientsig[0]);
		//clientsig[0] = 0x08;
		Log(LOGDEBUG, "%s: Client type: %02X\n", __FUNCTION__, clientsig[0]);

		//clientsig[0] = 0x08;

		/*clientsig[1] = 0x00;
		clientsig[2] = 0x00;
		clientsig[3] = 0x04;
		clientsig[4] = 0x60;
		
		clientsig[5] = 128; 
                clientsig[6] = 0;
                clientsig[7] = 1;
                clientsig[8] = 2;
		clientsig[9] = 0xBE;
		clientsig[10] = 0xF6;

		//*/
	} else {
		memset(&clientsig[5], 0, 4);
	}

	// generate random data
#ifdef _DEBUG
	for(int i=9; i<=RTMP_SIG_SIZE; i++)
		clientsig[i] = 0;//(char)(rand() % 256);//0xff;
#else
	for(int i=9; i<=RTMP_SIG_SIZE; i++)
	        clientsig[i] = (char)(rand() % 256);
#endif

	int dhposClient = 0;
	RC4_KEY *keyIn = 0;
	RC4_KEY *keyOut = 0;

	if(encrypted) {
		// generate Diffie-Hellmann parameters
		Link.dh = DHInit(1024);
		if(!Link.dh) {
			Log(LOGERROR, "%s: Couldn't initialize Diffie-Hellmann!", __FUNCTION__);
			return false;
		}

		dhposClient = GetDHOffset1(&clientsig[1], RTMP_SIG_SIZE);
		Log(LOGDEBUG, "%s: DH pubkey position: %d", __FUNCTION__, dhposClient);

		if(!DHGenerateKey(Link.dh)) {
			Log(LOGERROR, "%s: Couldn't generate Diffie-Hellmann public key!", __FUNCTION__);
			return false;
		}

		if(!DHGetPublicKey(Link.dh, (uint8_t*)&clientsig[1+dhposClient], 128)) {
			Log(LOGERROR, "%s: Couldn't write public key!", __FUNCTION__);
			return false;
		}
	}

	// set handshake digest
	if(FP9HandShake)
	{
		int digestPosClient = GetDigestOffset1(clientsig+1, RTMP_SIG_SIZE); // maybe reuse this value in verification
		Log(LOGDEBUG, "%s: Client digest offset: %d", __FUNCTION__, digestPosClient);
		
		CalculateDigest(digestPosClient, clientsig+1, GenuineFPKey, 30, &clientsig[1+digestPosClient]);
		
		Log(LOGDEBUG, "%s: Initial client digest: ", __FUNCTION__);
		LogHex(LOGDEBUG, (char *)clientsig+1+digestPosClient, SHA256_DIGEST_LENGTH);
	}

	#ifdef _DEBUG
	Log(LOGDEBUG, "Clientsig: ");
	LogHex(LOGDEBUG, &clientsig[1], RTMP_SIG_SIZE);
	#endif

	if(!WriteN(clientsig, RTMP_SIG_SIZE + 1))
		return false;

	char type;
	if(ReadN(&type, 1) != 1) // 0x03 or 0x06
		return false;

	Log(LOGDEBUG, "%s: Type Answer   : %02X", __FUNCTION__, type);

	if(type != clientsig[0])
		Log(LOGWARNING, "%s: Type mismatch: client sent %d, server answered %d", __FUNCTION__, clientsig[0], type);

	if(ReadN(serversig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
		return false;

	// decode server response
	uint32_t suptime;

	memcpy(&suptime, serversig, 4);
	suptime = ntohl(suptime);

	Log(LOGDEBUG, "%s: Server Uptime : %d", __FUNCTION__, suptime);
	Log(LOGDEBUG, "%s: FMS Version   : %d.%d.%d.%d", __FUNCTION__, serversig[4], serversig[5], serversig[6], serversig[7]);

	#ifdef _DEBUG
	Log(LOGDEBUG,"Server signature:");
	LogHex(LOGDEBUG, serversig, RTMP_SIG_SIZE);
	#endif

	if (!FP9HandShake) {
		if(!WriteN(serversig, RTMP_SIG_SIZE))
			return false;
	}

	// we have to use this signature now to find the correct algorithms for getting the digest and DH positions
	int digestPosServer = GetDigestOffset2(serversig, RTMP_SIG_SIZE);
	int dhposServer     = GetDHOffset2(serversig, RTMP_SIG_SIZE);

	if(FP9HandShake && !VerifyDigest(digestPosServer, serversig, GenuineFMSKey, 36)) {
        	Log(LOGWARNING, "Trying different position for server digest!\n");
                digestPosServer = GetDigestOffset1(serversig, RTMP_SIG_SIZE);
		dhposServer     = GetDHOffset1(serversig, RTMP_SIG_SIZE);

                if(!VerifyDigest(digestPosServer, serversig, GenuineFMSKey, 36)) {
                	Log(LOGERROR, "Couldn't verify the server digest\n");//,  continuing anyway, will probably fail!\n");
                	return false;
		}
        }

	Log(LOGDEBUG, "%s: Server DH public key offset: %d", __FUNCTION__, dhposServer);

	// generate SWFVerification token (SHA256 HMAC hash of decompressed SWF, key are the last 32 bytes of the server handshake)
	if(Link.SWFHash) {
		const char swfVerify[] = {0x01,0x01};

		memcpy(Link.SWFVerificationResponse, swfVerify, 2);
		EncodeInt32(&Link.SWFVerificationResponse[2], Link.SWFSize);
		EncodeInt32(&Link.SWFVerificationResponse[6], Link.SWFSize);
		HMACsha256(Link.SWFHash, SHA256_DIGEST_LENGTH, &serversig[RTMP_SIG_SIZE-SHA256_DIGEST_LENGTH], SHA256_DIGEST_LENGTH, &Link.SWFVerificationResponse[10]);
	}

	// do Diffie-Hellmann Key exchange for encrypted RTMP
	if(encrypted) {
		// compute secret key	
		uint8_t secretKey[128] = {0};
	
		//Log(LOGDEBUG, "Expecting secure key at %d\nKeys at ", dhposServer);
		//int i;
		//int len=0;
		int len = DHComputeSharedSecretKey(Link.dh, (uint8_t *)&serversig[dhposServer], 128, secretKey);
		if(len < 0) {
			Log(LOGDEBUG, "%s: Wrong secret key position!", __FUNCTION__);
			return false;
		}

		/*
		printf("sigpos: %d\n", sigpos);
		for(i=8; i<1535-128; i++) {
			if(i+128 < sigpos || i > sigpos+SHA256_DIGEST_LENGTH) {
				int len1 = DHComputeSharedSecretKey(Link.dh, (uint8_t *)&serversig[i], 128, secretKey);
				if(len1 > 0) {
				LogPrintf("%d,", i);
                        		//LogHex((char *)&serversig[i], 128);
				}
			}
		}
		LogPrintf("\n");//*/

		if(len < 0) {
			Log(LOGERROR, "%s: Couldn't compute secret key, the public key is probably insecure (FMS change?)\n", __FUNCTION__);
			exit(1);
			return false;
		}

		Log(LOGDEBUG, "%s: Secret key: ", __FUNCTION__);
		LogHex(LOGDEBUG, (char *)secretKey, 128);
		
		InitRC4Encryption(
			secretKey, 
			(uint8_t*)&serversig[dhposServer], 
			(uint8_t*)&clientsig[1+dhposClient],
			&keyIn,
			&keyOut);

		// well here is another interesting key, lets see what it is for!
		//HMACsha256(serversig, RTMP_SIG_SIZE, (char *)secretKey, 128, initialKey);
		//Log(LOGDEBUG, "%s: Calculated initial key:", __FUNCTION__);
		//LogHex(initialKey, SHA256_DIGEST_LENGTH);
	}

	// 2nd part of handshake
	char resp[RTMP_SIG_SIZE];
	if(ReadN(resp, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
		return false;

	#ifdef _DEBUG
	Log(LOGDEBUG, "%s: 2nd handshake: ", __FUNCTION__);
	LogHex(LOGDEBUG, resp, RTMP_SIG_SIZE);
	#endif

	if(FP9HandShake && resp[4] == 0 && resp[5] == 0 && resp[6] == 0 && resp[7] == 0) {
		Log(LOGDEBUG, "%s: Wait, did the server just refuse signed authetication?", __FUNCTION__);
	}

	if(!FP9HandShake) {
		if(memcmp(resp, clientsig + 1, RTMP_SIG_SIZE) != 0) {
			Log(LOGWARNING, "%s: client signature does not match!", __FUNCTION__);
		}

	} else {
		// verify server response
		int digestPosClient = GetDigestOffset1(clientsig+1, RTMP_SIG_SIZE);
	
		char signature[SHA256_DIGEST_LENGTH];
                char digest[SHA256_DIGEST_LENGTH];

		Log(LOGDEBUG, "%s: Client signature digest position: %d", __FUNCTION__, digestPosClient);

		HMACsha256(&clientsig[1+digestPosClient], SHA256_DIGEST_LENGTH, GenuineFMSKey, sizeof(GenuineFMSKey), digest);
		HMACsha256(resp, RTMP_SIG_SIZE-SHA256_DIGEST_LENGTH, digest, SHA256_DIGEST_LENGTH, signature);

		// show some information
		Log(LOGDEBUG, "%s: Digest key: ", __FUNCTION__);
		LogHex(LOGDEBUG, digest, SHA256_DIGEST_LENGTH);

		Log(LOGDEBUG, "%s: Signature calculated:", __FUNCTION__);
		LogHex(LOGDEBUG, signature, SHA256_DIGEST_LENGTH);

		Log(LOGDEBUG, "%s: Server sent signature:", __FUNCTION__);
		LogHex(LOGDEBUG, &resp[RTMP_SIG_SIZE-SHA256_DIGEST_LENGTH], SHA256_DIGEST_LENGTH);

		if(memcmp(signature, &resp[RTMP_SIG_SIZE-SHA256_DIGEST_LENGTH], SHA256_DIGEST_LENGTH) != 0) {
			Log(LOGWARNING, "%s: Server not genuine Adobe!", __FUNCTION__);
			return false;
		} else {
			Log(LOGDEBUG, "%s: Genuine Adobe Flash Media Server", __FUNCTION__);
		}
		
		// generate signed answer
		char clientResp[RTMP_SIG_SIZE]; 
#ifdef _DEBUG
        	for(int i=0; i<RTMP_SIG_SIZE; i++)
                	clientResp[i] = 0;//(char)(rand() % 256);//0xff;
#else
        	for(int i=0; i<RTMP_SIG_SIZE; i++)
                	clientResp[i] = (char)(rand() % 256);
#endif

		// calculate response now
                char signatureResp[SHA256_DIGEST_LENGTH];
                char digestResp[SHA256_DIGEST_LENGTH];

		HMACsha256(&serversig[digestPosServer], SHA256_DIGEST_LENGTH, GenuineFPKey, sizeof(GenuineFPKey), digestResp);
		HMACsha256(clientResp, RTMP_SIG_SIZE-SHA256_DIGEST_LENGTH, digestResp, SHA256_DIGEST_LENGTH, signatureResp);

		// some info output
		Log(LOGDEBUG, "%s: Calculated digest key from secure key and server digest: ", __FUNCTION__);
                LogHex(LOGDEBUG, digestResp, SHA256_DIGEST_LENGTH);

                Log(LOGDEBUG, "%s: Client signature calculated:", __FUNCTION__);
                LogHex(LOGDEBUG, signatureResp, SHA256_DIGEST_LENGTH);

		memcpy(&clientResp[RTMP_SIG_SIZE-SHA256_DIGEST_LENGTH], signatureResp, SHA256_DIGEST_LENGTH);

		#ifdef _DEBUG
		Log(LOGDEBUG, "%s: Sending final signed handshake response: ", __FUNCTION__);
		LogHex(LOGDEBUG, clientResp, RTMP_SIG_SIZE);
		#endif

		if(!WriteN(clientResp, RTMP_SIG_SIZE))
			return false;
	}
	
	if(encrypted) {
		// set keys for encryption from now on
        	Link.rc4keyIn  = keyIn;
        	Link.rc4keyOut = keyOut;

		char buff[RTMP_SIG_SIZE];

		// update the keystreams 
		if(Link.rc4keyIn) {
                	RC4(Link.rc4keyIn, RTMP_SIG_SIZE, (uint8_t*)buff, (uint8_t*)buff);
        	}

		if(Link.rc4keyOut) {
	        	RC4(Link.rc4keyOut, RTMP_SIG_SIZE, (uint8_t*)buff, (uint8_t*)buff);
		}
	}
	
	Log(LOGDEBUG, "%s: Handshaking finished....", __FUNCTION__);
	return true;
}


