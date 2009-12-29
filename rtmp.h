#ifndef __RTMP_H__
#define __RTMP_H__
/*
 *      Copyright (C) 2005-2008 Team XBMC
 *      http://www.xbmc.org
 *      Copyright (C) 2008-2009 Andrej Stepanchuk
 *      Copyright (C) 2009 Howard Chu
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

#ifdef WIN32
#include <winsock.h>
#define	GetSockError()	WSAGetLastError()
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#define	GetSockError()	errno
#endif

#include <stdint.h>

#include "log.h"
#include "amf.h"

#define RTMP_PROTOCOL_UNDEFINED	-1
#define RTMP_PROTOCOL_RTMP      0
#define RTMP_PROTOCOL_RTMPT     1	// not yet supported
#define RTMP_PROTOCOL_RTMPS     2	// not yet supported
#define RTMP_PROTOCOL_RTMPE     3
#define RTMP_PROTOCOL_RTMPTE    4	// not yet supported
#define RTMP_PROTOCOL_RTMFP     5	// not yet supported

#define RTMP_DEFAULT_CHUNKSIZE	128

#define RTMP_BUFFER_CACHE_SIZE (16*1024) // needs to fit largest number of bytes recv() may return

#define	RTMP_CHANNELS	65600

extern const char RTMPProtocolStringsLower[][7];
extern bool RTMP_ctrlC;

uint32_t RTMP_GetTime();

#define RTMP_PACKET_TYPE_AUDIO 0x08
#define RTMP_PACKET_TYPE_VIDEO 0x09
#define RTMP_PACKET_TYPE_INFO  0x12

#define RTMP_MAX_HEADER_SIZE 14

typedef unsigned char BYTE;

typedef struct RTMPPacket
{
  BYTE m_headerType;
  BYTE m_packetType;
  int m_nChannel;
  int32_t m_nInfoField1;	// 3 first bytes
  int32_t m_nInfoField2;	// last 4 bytes in a long header, absolute timestamp for long headers, relative timestamp for short headers
  bool m_hasAbsTimestamp;	// timestamp absolute or relative?
  uint32_t m_nTimeStamp;	// absolute timestamp
  uint32_t m_nBodySize;
  uint32_t m_nBytesRead;
  char *m_body;
} RTMPPacket;

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

  double seekTime;
  uint32_t length;
  bool bLiveStream;

  long int timeout;		// number of seconds before connection times out

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

typedef struct RTMP
{
  int m_socket;
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
  bool m_bPlaying;
  bool m_bTimedout;

  AVal *m_methodCalls;		/* remote method calls queue */
  int m_numCalls;

  RTMP_LNK Link;
  char *m_pBufferStart;		// pointer into m_pBuffer of next byte to process
  int m_nBufferSize;		// number of unprocessed bytes in buffer
  RTMPPacket *m_vecChannelsIn[RTMP_CHANNELS];
  RTMPPacket *m_vecChannelsOut[RTMP_CHANNELS];
  int m_channelTimestamp[RTMP_CHANNELS];	// abs timestamp of last packet

  double m_fAudioCodecs;	// audioCodecs for the connect packet
  double m_fVideoCodecs;	// videoCodecs for the connect packet
  double m_fEncoding;		/* AMF0 or AMF3 */

  double m_fDuration;		// duration of stream in seconds
  char m_pBuffer[RTMP_BUFFER_CACHE_SIZE];		// data read from socket
} RTMP;

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

bool RTMP_Connect(RTMP *r);
bool RTMP_Serve(RTMP *r);

bool RTMP_ReadPacket(RTMP * r, RTMPPacket * packet);
bool RTMP_SendPacket(RTMP * r, RTMPPacket * packet, bool queue);
bool RTMP_IsConnected(RTMP *r);
bool RTMP_IsTimedout(RTMP *r);
double RTMP_GetDuration(RTMP *r);
bool RTMP_ToggleStream(RTMP *r);

bool RTMP_ConnectStream(RTMP *r, double seekTime, uint32_t dLength);
bool RTMP_ReconnectStream(RTMP *r, int bufferTime, double seekTime, uint32_t dLength);
void RTMP_DeleteStream(RTMP *r);
int RTMP_GetNextMediaPacket(RTMP *r, RTMPPacket *packet);

void RTMP_Init(RTMP *r);
void RTMP_Close(RTMP *r);

bool RTMP_SendCtrl(RTMP * r, short nType, unsigned int nObject, unsigned int nTime);
bool RTMP_SendPause(RTMP *r, bool DoPause, double dTime);
bool RTMP_FindFirstMatchingProperty(AMFObject *obj, const AVal *name,
				      AMFObjectProperty *p);


#endif
