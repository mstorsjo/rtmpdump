#ifndef __RTMP_H__
#define __RTMP_H__
/*
 *      Copyright (C) 2005-2008 Team XBMC
 *      http://www.xbmc.org
 *      Copyright (C) 2008-2009 Andrej Stepanchuk
 *      Copyright (C) 2009-2010 Howard Chu
 *
 *  This file is part of librtmp.
 *
 *  librtmp is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  librtmp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with librtmp see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

#define CRYPTO

#include <errno.h>
#include <stdint.h>

#include "amf.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define RTMP_FEATURE_HTTP	0x01
#define RTMP_FEATURE_ENC	0x02
#define RTMP_FEATURE_SSL	0x04
#define RTMP_FEATURE_MFP	0x08	// not yet supported

#define RTMP_PROTOCOL_UNDEFINED	-1
#define RTMP_PROTOCOL_RTMP      0
#define RTMP_PROTOCOL_RTMPE     RTMP_FEATURE_ENC
#define RTMP_PROTOCOL_RTMPT     RTMP_FEATURE_HTTP
#define RTMP_PROTOCOL_RTMPS     (RTMP_FEATURE_HTTP|RTMP_FEATURE_SSL)
#define RTMP_PROTOCOL_RTMPTE    (RTMP_FEATURE_HTTP|RTMP_FEATURE_ENC)
#define RTMP_PROTOCOL_RTMFP     RTMP_FEATURE_MFP

#define RTMP_DEFAULT_CHUNKSIZE	128

#define RTMP_BUFFER_CACHE_SIZE (16*1024)	// needs to fit largest number of bytes recv() may return

#define	RTMP_CHANNELS	65600

  extern const char RTMPProtocolStringsLower[][7];
  extern const AVal RTMP_DefaultFlashVer;
  extern bool RTMP_ctrlC;

  uint32_t RTMP_GetTime();

#define RTMP_PACKET_TYPE_AUDIO 0x08
#define RTMP_PACKET_TYPE_VIDEO 0x09
#define RTMP_PACKET_TYPE_INFO  0x12

#define RTMP_MAX_HEADER_SIZE 18

#define RTMP_PACKET_SIZE_LARGE    0
#define RTMP_PACKET_SIZE_MEDIUM   1
#define RTMP_PACKET_SIZE_SMALL    2
#define RTMP_PACKET_SIZE_MINIMUM  3

  typedef unsigned char BYTE;

  typedef struct RTMPChunk
  {
    int c_headerSize;
    int c_chunkSize;
    char *c_chunk;
    char c_header[RTMP_MAX_HEADER_SIZE];
  } RTMPChunk;

  typedef struct RTMPPacket
  {
    BYTE m_headerType;
    BYTE m_packetType;
    BYTE m_hasAbsTimestamp;	// timestamp absolute or relative?
    int m_nChannel;
    uint32_t m_nInfoField1;	// 3 first bytes
    int32_t m_nInfoField2;	// last 4 bytes in a long header, absolute timestamp for long headers, relative timestamp for short headers
    uint32_t m_nTimeStamp;	// absolute timestamp
    uint32_t m_nBodySize;
    uint32_t m_nBytesRead;
    RTMPChunk *m_chunk;
    char *m_body;
  } RTMPPacket;

  typedef struct RTMPSockBuf
  {
    int sb_socket;
    int sb_size;		/* number of unprocessed bytes in buffer */
    char *sb_start;		/* pointer into sb_pBuffer of next byte to process */
    char sb_buf[RTMP_BUFFER_CACHE_SIZE];	/* data read from socket */
    bool sb_timedout;
    void *sb_ssl;
  } RTMPSockBuf;

  void RTMPPacket_Reset(RTMPPacket *p);
  void RTMPPacket_Dump(RTMPPacket *p);
  bool RTMPPacket_Alloc(RTMPPacket *p, int nSize);
  void RTMPPacket_Free(RTMPPacket *p);

#define RTMPPacket_IsReady(a)	((a)->m_nBytesRead == (a)->m_nBodySize)

  typedef struct RTMP_LNK
  {
    const char *hostname;
    unsigned int port;
    int protocol;

    AVal playpath;
    AVal tcUrl;
    AVal swfUrl;
    AVal pageUrl;
    AVal app;
    AVal auth;
    AVal flashVer;
    AVal subscribepath;
    AVal token;
    AVal playpath0;
    AMFObject extras;

    double seekTime;
    uint32_t length;
    bool authflag;
    bool bLiveStream;

    int timeout;		// number of seconds before connection times out

    const char *sockshost;
    unsigned short socksport;

#ifdef CRYPTO
    void *dh;			// for encryption
    void *rc4keyIn;
    void *rc4keyOut;

    AVal SWFHash;
    uint32_t SWFSize;
    char SWFVerificationResponse[42];
#endif
  } RTMP_LNK;

  /* state for read() wrapper */
  typedef struct RTMP_READ
  {
    char *buf;
    char *bufpos;
    unsigned int buflen;
    uint32_t timestamp;
    uint8_t dataType;
    uint8_t bResume;
    uint8_t bDidHeader;
    int8_t status;
#define RTMP_READ_COMPLETE	-3
#define RTMP_READ_ERROR	-2
#define RTMP_READ_EOF	-1
#define RTMP_READ_IGNORE	0

    /* if bResume == TRUE */
    uint8_t initialFrameType;
    uint8_t bStopIgnoring;
    uint8_t bFoundKeyframe;
    uint8_t bFoundFlvKeyframe;
    uint32_t nResumeTS;
    char *metaHeader;
    char *initialFrame;
    uint32_t nMetaHeaderSize;
    uint32_t nInitialFrameSize;
    uint32_t nIgnoredFrameCounter;
    uint32_t nIgnoredFlvFrameCounter;
  } RTMP_READ;

  typedef struct RTMP
  {
    int m_inChunkSize;
    int m_outChunkSize;
    int m_nBWCheckCounter;
    int m_nBytesIn;
    int m_nBytesInSent;
    int m_nBufferMS;
    int m_stream_id;		// returned in _result from invoking createStream
    int m_mediaChannel;
    uint32_t m_mediaStamp;
    uint32_t m_pauseStamp;
    int m_pausing;
    int m_nServerBW;
    int m_nClientBW;
    uint8_t m_nClientBW2;
    uint8_t m_bPlaying;
    uint8_t m_bSendEncoding;
    uint8_t m_bSendCounter;

    AVal *m_methodCalls;	/* remote method calls queue */
    int m_numCalls;

    RTMP_LNK Link;
    RTMPPacket *m_vecChannelsIn[RTMP_CHANNELS];
    RTMPPacket *m_vecChannelsOut[RTMP_CHANNELS];
    int m_channelTimestamp[RTMP_CHANNELS];	// abs timestamp of last packet

    double m_fAudioCodecs;	// audioCodecs for the connect packet
    double m_fVideoCodecs;	// videoCodecs for the connect packet
    double m_fEncoding;		/* AMF0 or AMF3 */

    double m_fDuration;		// duration of stream in seconds

    int m_msgCounter;		/* RTMPT stuff */
    int m_polling;
    int m_resplen;
    int m_unackd;
    AVal m_clientID;

    RTMP_READ m_read;
    RTMPSockBuf m_sb;
  } RTMP;

  bool RTMP_ParseURL(const char *url, int *protocol, char **host,
		     unsigned int *port, AVal *playpath, AVal *app);
  void RTMP_ParsePlaypath(AVal *in, AVal *out);
  void RTMP_SetBufferMS(RTMP *r, int size);
  void RTMP_UpdateBufferMS(RTMP *r);

  void RTMP_SetupStream(RTMP *r, int protocol,
			const char *hostname,
			unsigned int port,
			const char *sockshost,
			AVal *playpath,
			AVal *tcUrl,
			AVal *swfUrl,
			AVal *pageUrl,
			AVal *app,
			AVal *auth,
			AVal *swfSHA256Hash,
			uint32_t swfSize,
			AVal *flashVer,
			AVal *subscribepath,
			double dTime,
			uint32_t dLength, bool bLiveStream, long int timeout);

  bool RTMP_Connect(RTMP *r, RTMPPacket *cp);
  bool RTMP_Connect0(RTMP *r, struct sockaddr *svc);
  bool RTMP_Connect1(RTMP *r, RTMPPacket *cp);
  bool RTMP_Serve(RTMP *r);

  bool RTMP_ReadPacket(RTMP *r, RTMPPacket *packet);
  bool RTMP_SendPacket(RTMP *r, RTMPPacket *packet, bool queue);
  bool RTMP_SendChunk(RTMP *r, RTMPChunk *chunk);
  bool RTMP_IsConnected(RTMP *r);
  bool RTMP_IsTimedout(RTMP *r);
  double RTMP_GetDuration(RTMP *r);
  bool RTMP_ToggleStream(RTMP *r);

  bool RTMP_ConnectStream(RTMP *r, double seekTime, uint32_t dLength);
  bool RTMP_ReconnectStream(RTMP *r, int bufferTime, double seekTime,
			    uint32_t dLength);
  void RTMP_DeleteStream(RTMP *r);
  int RTMP_GetNextMediaPacket(RTMP *r, RTMPPacket *packet);
  int RTMP_ClientPacket(RTMP *r, RTMPPacket *packet);

  void RTMP_Init(RTMP *r);
  void RTMP_Close(RTMP *r);

  bool RTMP_SendCtrl(RTMP *r, short nType, unsigned int nObject,
		     unsigned int nTime);
  bool RTMP_SendPause(RTMP *r, bool DoPause, double dTime);
  bool RTMP_FindFirstMatchingProperty(AMFObject *obj, const AVal *name,
				      AMFObjectProperty * p);

  int RTMPSockBuf_Fill(RTMPSockBuf *sb);
  int RTMPSockBuf_Send(RTMPSockBuf *sb, const char *buf, int len);
  int RTMPSockBuf_Close(RTMPSockBuf *sb);

  bool RTMP_SendCreateStream(RTMP *r, double dCmdID);
  bool RTMP_SendSeek(RTMP *r, double dTime);
  bool RTMP_SendServerBW(RTMP *r);
  void RTMP_DropRequest(RTMP *r, int i, bool freeit);
  int RTMP_Read(RTMP *r, char *buf, int size);

#ifdef CRYPTO
/* hashswf.c */
#define HASHLEN	32

  int RTMP_HashSWF(const char *url, unsigned int *size, unsigned char *hash,
		   int age);
#endif

#ifdef __cplusplus
};
#endif

#endif
