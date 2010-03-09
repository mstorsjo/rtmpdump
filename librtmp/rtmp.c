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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "rtmp.h"
#include "log.h"

#include <openssl/ssl.h>

#ifdef CRYPTO
#include <openssl/rc4.h>
#endif

#define RTMP_SIG_SIZE 1536
#define RTMP_LARGE_HEADER_SIZE 12

SSL_CTX *RTMP_ssl_ctx;
static const int packetSize[] = { 12, 8, 4, 1 };

bool RTMP_ctrlC;

const char RTMPProtocolStrings[][7] = {
  "RTMP",
  "RTMPT",
  "RTMPE",
  "RTMPTE",
  "",
  "RTMPS",
  "",
  "",
  "RTMFP"
};

const char RTMPProtocolStringsLower[][7] = {
  "rtmp",
  "rtmpt",
  "rtmpe",
  "rtmpte",
  "",
  "rtmps",
  "",
  "",
  "rtmfp"
};

static bool DumpMetaData(AMFObject *obj);
static bool HandShake(RTMP *r, bool FP9HandShake);
static bool SocksNegotiate(RTMP *r);

static bool SendConnectPacket(RTMP *r, RTMPPacket *cp);
static bool SendCheckBW(RTMP *r);
static bool SendCheckBWResult(RTMP *r, double txn);
static bool SendDeleteStream(RTMP *r, double dStreamId);
static bool SendFCSubscribe(RTMP *r, AVal *subscribepath);
static bool SendPlay(RTMP *r);
static bool SendBytesReceived(RTMP *r);

#if 0				/* unused */
static bool SendBGHasStream(RTMP *r, double dId, AVal *playpath);
#endif

static int HandleInvoke(RTMP *r, const char *body, unsigned int nBodySize);
static bool HandleMetadata(RTMP *r, char *body, unsigned int len);
static void HandleChangeChunkSize(RTMP *r, const RTMPPacket *packet);
static void HandleAudio(RTMP *r, const RTMPPacket *packet);
static void HandleVideo(RTMP *r, const RTMPPacket *packet);
static void HandleCtrl(RTMP *r, const RTMPPacket *packet);
static void HandleServerBW(RTMP *r, const RTMPPacket *packet);
static void HandleClientBW(RTMP *r, const RTMPPacket *packet);

static int ReadN(RTMP *r, char *buffer, int n);
static bool WriteN(RTMP *r, const char *buffer, int n);

static void DecodeTEA(AVal *key, AVal *text);

uint32_t
RTMP_GetTime()
{
#ifdef _DEBUG
  return 0;
#elif defined(WIN32)
  return timeGetTime();
#else
  struct tms t;
  return times(&t) * 1000 / sysconf(_SC_CLK_TCK);
#endif
}

void
RTMPPacket_Reset(RTMPPacket *p)
{
  p->m_headerType = 0;
  p->m_packetType = 0;
  p->m_nChannel = 0;
  p->m_nInfoField1 = 0;
  p->m_nInfoField2 = 0;
  p->m_hasAbsTimestamp = false;
  p->m_nBodySize = 0;
  p->m_nBytesRead = 0;
}

bool
RTMPPacket_Alloc(RTMPPacket *p, int nSize)
{
  char *ptr = calloc(1, nSize + RTMP_MAX_HEADER_SIZE);
  if (!ptr)
    return false;
  p->m_body = ptr + RTMP_MAX_HEADER_SIZE;
  p->m_nBytesRead = 0;
  return true;
}

void
RTMPPacket_Free(RTMPPacket *p)
{
  if (p->m_body)
    {
      free(p->m_body - RTMP_MAX_HEADER_SIZE);
      p->m_body = NULL;
    }
}

void
RTMPPacket_Dump(RTMPPacket *p)
{
  Log(LOGDEBUG,
      "RTMP PACKET: packet type: 0x%02x. channel: 0x%02x. info 1: %d info 2: %d. Body size: %lu. body: 0x%02x",
      p->m_packetType, p->m_nChannel, p->m_nInfoField1, p->m_nInfoField2,
      p->m_nBodySize, p->m_body ? (unsigned char)p->m_body[0] : 0);
}

void
RTMP_SSL_Init()
{
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_digests();
  RTMP_ssl_ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_options(RTMP_ssl_ctx, SSL_OP_ALL);
  SSL_CTX_set_default_verify_paths(RTMP_ssl_ctx);
}

void
RTMP_Init(RTMP *r)
{
  int i;

  if (!RTMP_ssl_ctx)
    RTMP_SSL_Init();

  for (i = 0; i < RTMP_CHANNELS; i++)
    {
      r->m_vecChannelsIn[i] = NULL;
      r->m_vecChannelsOut[i] = NULL;
    }
  r->m_sb.sb_socket = -1;
  RTMP_Close(r);
  r->m_nBufferMS = 300;
  r->m_fDuration = 0;
  r->m_sb.sb_start = NULL;
  r->m_fAudioCodecs = 3191.0;
  r->m_fVideoCodecs = 252.0;
  r->m_fEncoding = 0.0;
  r->m_sb.sb_timedout = false;
  r->m_pausing = 0;
  r->m_mediaChannel = 0;
}

double
RTMP_GetDuration(RTMP *r)
{
  return r->m_fDuration;
}

bool
RTMP_IsConnected(RTMP *r)
{
  return r->m_sb.sb_socket != -1;
}

bool
RTMP_IsTimedout(RTMP *r)
{
  return r->m_sb.sb_timedout;
}

void
RTMP_SetBufferMS(RTMP *r, int size)
{
  r->m_nBufferMS = size;
}

void
RTMP_UpdateBufferMS(RTMP *r)
{
  RTMP_SendCtrl(r, 3, r->m_stream_id, r->m_nBufferMS);
}

#undef OSS
#ifdef WIN32
#define OSS	"WIN"
#elif defined(__sun__)
#define OSS	"SOL"
#elif defined(__APPLE__)
#define OSS	"MAC"
#elif defined(__linux__)
#define OSS	"LNX"
#else
#define OSS	"GNU"
#endif
static const char DEFAULT_FLASH_VER[] = OSS " 10,0,32,18";
const AVal RTMP_DefaultFlashVer =
  { (char *)DEFAULT_FLASH_VER, sizeof(DEFAULT_FLASH_VER) - 1 };

void
RTMP_SetupStream(RTMP *r,
		 int protocol,
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
		 uint32_t dLength, bool bLiveStream, long int timeout)
{
  assert(protocol < 9);

  Log(LOGDEBUG, "Protocol : %s", RTMPProtocolStrings[protocol]);
  Log(LOGDEBUG, "Hostname : %s", hostname);
  Log(LOGDEBUG, "Port     : %d", port);
  Log(LOGDEBUG, "Playpath : %s", playpath->av_val);

  if (tcUrl && tcUrl->av_val)
    Log(LOGDEBUG, "tcUrl    : %s", tcUrl->av_val);
  if (swfUrl && swfUrl->av_val)
    Log(LOGDEBUG, "swfUrl   : %s", swfUrl->av_val);
  if (pageUrl && pageUrl->av_val)
    Log(LOGDEBUG, "pageUrl  : %s", pageUrl->av_val);
  if (app && app->av_val)
    Log(LOGDEBUG, "app      : %.*s", app->av_len, app->av_val);
  if (auth && auth->av_val)
    Log(LOGDEBUG, "auth     : %s", auth->av_val);
  if (subscribepath && subscribepath->av_val)
    Log(LOGDEBUG, "subscribepath : %s", subscribepath->av_val);
  if (flashVer && flashVer->av_val)
    Log(LOGDEBUG, "flashVer : %s", flashVer->av_val);
  if (dTime > 0)
    Log(LOGDEBUG, "SeekTime      : %.3f sec", (double)dTime / 1000.0);
  if (dLength > 0)
    Log(LOGDEBUG, "playLength    : %.3f sec", (double)dLength / 1000.0);

  Log(LOGDEBUG, "live     : %s", bLiveStream ? "yes" : "no");
  Log(LOGDEBUG, "timeout  : %d sec", timeout);

#ifdef CRYPTO
  if (swfSHA256Hash != NULL && swfSize > 0)
    {
      r->Link.SWFHash = *swfSHA256Hash;
      r->Link.SWFSize = swfSize;
      Log(LOGDEBUG, "SWFSHA256:");
      LogHex(LOGDEBUG, r->Link.SWFHash.av_val, 32);
      Log(LOGDEBUG, "SWFSize  : %lu", r->Link.SWFSize);
    }
  else
    {
      r->Link.SWFHash.av_len = 0;
      r->Link.SWFHash.av_val = NULL;
      r->Link.SWFSize = 0;
    }
#endif

  if (sockshost)
    {
      const char *socksport = strchr(sockshost, ':');
      char *hostname = strdup(sockshost);

      if (socksport)
	hostname[socksport - sockshost] = '\0';
      r->Link.sockshost = hostname;

      r->Link.socksport = socksport ? atoi(socksport + 1) : 1080;
      Log(LOGDEBUG, "Connecting via SOCKS proxy: %s:%d", r->Link.sockshost,
	  r->Link.socksport);
    }
  else
    {
      r->Link.sockshost = NULL;
      r->Link.socksport = 0;
    }

  if (tcUrl && tcUrl->av_len)
    r->Link.tcUrl = *tcUrl;
  if (swfUrl && swfUrl->av_len)
    r->Link.swfUrl = *swfUrl;
  if (pageUrl && pageUrl->av_len)
    r->Link.pageUrl = *pageUrl;
  if (app && app->av_len)
    r->Link.app = *app;
  if (auth && auth->av_len)
    r->Link.auth = *auth;
  if (flashVer && flashVer->av_len)
    r->Link.flashVer = *flashVer;
  else
    r->Link.flashVer = RTMP_DefaultFlashVer;
  if (subscribepath && subscribepath->av_len)
    r->Link.subscribepath = *subscribepath;
  r->Link.seekTime = dTime;
  r->Link.length = dLength;
  r->Link.bLiveStream = bLiveStream;
  r->Link.timeout = timeout;

  r->Link.protocol = protocol;
  r->Link.hostname = hostname;
  r->Link.port = port;
  r->Link.playpath = *playpath;

  if (r->Link.port == 0)
    r->Link.port = 1935;
}

static bool
add_addr_info(struct sockaddr_in *service, const char *hostname, int port)
{
  service->sin_addr.s_addr = inet_addr(hostname);
  if (service->sin_addr.s_addr == INADDR_NONE)
    {
      struct hostent *host = gethostbyname(hostname);
      if (host == NULL || host->h_addr == NULL)
	{
	  Log(LOGERROR, "Problem accessing the DNS. (addr: %s)", hostname);
	  return false;
	}
      service->sin_addr = *(struct in_addr *)host->h_addr;
    }

  service->sin_port = htons(port);
  return true;
}

bool
RTMP_Connect0(RTMP *r, struct sockaddr * service)
{
  // close any previous connection
  RTMP_Close(r);

  r->m_sb.sb_timedout = false;
  r->m_pausing = 0;
  r->m_fDuration = 0.0;

  r->m_sb.sb_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (r->m_sb.sb_socket != -1)
    {
      if (connect(r->m_sb.sb_socket, service, sizeof(struct sockaddr)) < 0)
	{
	  int err = GetSockError();
	  Log(LOGERROR, "%s, failed to connect socket. %d (%s)",
	      __FUNCTION__, err, strerror(err));
	  RTMP_Close(r);
	  return false;
	}

      if (r->Link.socksport)
	{
	  Log(LOGDEBUG, "%s ... SOCKS negotiation", __FUNCTION__);
	  if (!SocksNegotiate(r))
	    {
	      Log(LOGERROR, "%s, SOCKS negotiation failed.", __FUNCTION__);
	      RTMP_Close(r);
	      return false;
	    }
	}
    }
  else
    {
      Log(LOGERROR, "%s, failed to create socket. Error: %d", __FUNCTION__,
	  GetSockError());
      return false;
    }

  // set timeout
  SET_RCVTIMEO(tv, r->Link.timeout);
  if (setsockopt
      (r->m_sb.sb_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)))
    {
      Log(LOGERROR, "%s, Setting socket timeout to %ds failed!",
	  __FUNCTION__, r->Link.timeout);
    }

  int on = 1;
  setsockopt(r->m_sb.sb_socket, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

  return true;
}

bool
RTMP_Connect1(RTMP *r, RTMPPacket *cp)
{
  if (r->Link.protocol & RTMP_FEATURE_SSL)
    {
      r->m_sb.sb_ssl = SSL_new(RTMP_ssl_ctx);
      SSL_set_fd(r->m_sb.sb_ssl, r->m_sb.sb_socket);
      if (SSL_connect(r->m_sb.sb_ssl) < 0)
	{
	  Log(LOGERROR, "%s, SSL_Connect failed", __FUNCTION__);
	  RTMP_Close(r);
	  return false;
	}
    }
  Log(LOGDEBUG, "%s, ... connected, handshaking", __FUNCTION__);
  if (!HandShake(r, true))
    {
      Log(LOGERROR, "%s, handshake failed.", __FUNCTION__);
      RTMP_Close(r);
      return false;
    }
  Log(LOGDEBUG, "%s, handshaked", __FUNCTION__);

  if (!SendConnectPacket(r, cp))
    {
      Log(LOGERROR, "%s, RTMP connect failed.", __FUNCTION__);
      RTMP_Close(r);
      return false;
    }
  return true;
}

bool
RTMP_Connect(RTMP *r, RTMPPacket *cp)
{
  struct sockaddr_in service;
  if (!r->Link.hostname)
    return false;

  memset(&service, 0, sizeof(struct sockaddr_in));
  service.sin_family = AF_INET;

  if (r->Link.socksport)
    {
      // Connect via SOCKS
      if (!add_addr_info(&service, r->Link.sockshost, r->Link.socksport))
	return false;
    }
  else
    {
      // Connect directly
      if (!add_addr_info(&service, r->Link.hostname, r->Link.port))
	return false;
    }

  if (!RTMP_Connect0(r, (struct sockaddr *)&service))
    return false;

  r->m_bSendCounter = true;

  return RTMP_Connect1(r, cp);
}

static bool
SocksNegotiate(RTMP *r)
{
  struct sockaddr_in service;
  memset(&service, 0, sizeof(struct sockaddr_in));

  add_addr_info(&service, r->Link.hostname, r->Link.port);
  unsigned long addr = htonl(service.sin_addr.s_addr);

  char packet[] = {
    4, 1,			// SOCKS 4, connect
    (r->Link.port >> 8) & 0xFF,
    (r->Link.port) & 0xFF,
    (char)(addr >> 24) & 0xFF, (char)(addr >> 16) & 0xFF,
    (char)(addr >> 8) & 0xFF, (char)addr & 0xFF,
    0
  };				// NULL terminate

  WriteN(r, packet, sizeof packet);

  if (ReadN(r, packet, 8) != 8)
    return false;

  if (packet[0] == 0 && packet[1] == 90)
    {
      return true;
    }
  else
    {
      Log(LOGERROR, "%s, SOCKS returned error code %d", packet[1]);
      return false;
    }
}

bool
RTMP_ConnectStream(RTMP *r, double seekTime, uint32_t dLength)
{
  RTMPPacket packet = { 0 };
  if (seekTime >= -2.0)
    r->Link.seekTime = seekTime;

  if (dLength >= 0)
    r->Link.length = dLength;

  r->m_mediaChannel = 0;

  while (!r->m_bPlaying && RTMP_IsConnected(r) && RTMP_ReadPacket(r, &packet))
    {
      if (RTMPPacket_IsReady(&packet))
	{
	  if (!packet.m_nBodySize)
	    continue;
	  if ((packet.m_packetType == RTMP_PACKET_TYPE_AUDIO) ||
	      (packet.m_packetType == RTMP_PACKET_TYPE_VIDEO) ||
	      (packet.m_packetType == RTMP_PACKET_TYPE_INFO))
	    {
	      Log(LOGWARNING, "Received FLV packet before play()! Ignoring.");
	      RTMPPacket_Free(&packet);
	      continue;
	    }

	  RTMP_ClientPacket(r, &packet);
	  RTMPPacket_Free(&packet);
	}
    }

  return r->m_bPlaying;
}

bool
RTMP_ReconnectStream(RTMP *r, int bufferTime, double seekTime,
		     uint32_t dLength)
{
  RTMP_DeleteStream(r);

  RTMP_SendCreateStream(r, 2.0);

  RTMP_SetBufferMS(r, bufferTime);

  return RTMP_ConnectStream(r, seekTime, dLength);
}

bool
RTMP_ToggleStream(RTMP *r)
{
  bool res;

  if (!r->m_pausing)
    {
      res = RTMP_SendPause(r, true, r->m_pauseStamp);
      if (!res)
	return res;

      r->m_pausing = 1;
      sleep(1);
    }
  res = RTMP_SendPause(r, false, r->m_pauseStamp);
  r->m_pausing = 3;
  return res;
}

void
RTMP_DeleteStream(RTMP *r)
{
  if (r->m_stream_id < 0)
    return;

  r->m_bPlaying = false;

  SendDeleteStream(r, r->m_stream_id);
}

int
RTMP_GetNextMediaPacket(RTMP *r, RTMPPacket *packet)
{
  int bHasMediaPacket = 0;

  while (!bHasMediaPacket && RTMP_IsConnected(r)
	 && RTMP_ReadPacket(r, packet))
    {
      if (!RTMPPacket_IsReady(packet))
	{
	  continue;
	}

      bHasMediaPacket = RTMP_ClientPacket(r, packet);

      if (!bHasMediaPacket)
	{
	  RTMPPacket_Free(packet);
	}
      else if (r->m_pausing == 3)
	{
	  if (packet->m_nTimeStamp <= r->m_mediaStamp)
	    {
	      bHasMediaPacket = 0;
#ifdef _DEBUG
	      Log(LOGDEBUG,
		  "Skipped type: %02X, size: %d, TS: %d ms, abs TS: %d, pause: %d ms",
		  packet->m_packetType, packet->m_nBodySize,
		  packet->m_nTimeStamp, packet->m_hasAbsTimestamp,
		  r->m_mediaStamp);
#endif
	      continue;
	    }
	  r->m_pausing = 0;
	}
    }

  if (bHasMediaPacket)
    r->m_bPlaying = true;
  else if (r->m_sb.sb_timedout && !r->m_pausing)
    r->m_pauseStamp = r->m_channelTimestamp[r->m_mediaChannel];

  return bHasMediaPacket;
}

int
RTMP_ClientPacket(RTMP *r, RTMPPacket *packet)
{
  int bHasMediaPacket = 0;
  switch (packet->m_packetType)
    {
    case 0x01:
      // chunk size
      HandleChangeChunkSize(r, packet);
      break;

    case 0x03:
      // bytes read report
      Log(LOGDEBUG, "%s, received: bytes read report", __FUNCTION__);
      break;

    case 0x04:
      // ctrl
      HandleCtrl(r, packet);
      break;

    case 0x05:
      // server bw
      HandleServerBW(r, packet);
      break;

    case 0x06:
      // client bw
      HandleClientBW(r, packet);
      break;

    case 0x08:
      // audio data
      //Log(LOGDEBUG, "%s, received: audio %lu bytes", __FUNCTION__, packet.m_nBodySize);
      HandleAudio(r, packet);
      bHasMediaPacket = 1;
      if (!r->m_mediaChannel)
	r->m_mediaChannel = packet->m_nChannel;
      if (!r->m_pausing)
	r->m_mediaStamp = packet->m_nTimeStamp;
      break;

    case 0x09:
      // video data
      //Log(LOGDEBUG, "%s, received: video %lu bytes", __FUNCTION__, packet.m_nBodySize);
      HandleVideo(r, packet);
      bHasMediaPacket = 1;
      if (!r->m_mediaChannel)
	r->m_mediaChannel = packet->m_nChannel;
      if (!r->m_pausing)
	r->m_mediaStamp = packet->m_nTimeStamp;
      break;

    case 0x0F:			// flex stream send
      Log(LOGDEBUG,
	  "%s, flex stream send, size %lu bytes, not supported, ignoring",
	  __FUNCTION__, packet->m_nBodySize);
      break;

    case 0x10:			// flex shared object
      Log(LOGDEBUG,
	  "%s, flex shared object, size %lu bytes, not supported, ignoring",
	  __FUNCTION__, packet->m_nBodySize);
      break;

    case 0x11:			// flex message
      {
	Log(LOGDEBUG,
	    "%s, flex message, size %lu bytes, not fully supported",
	    __FUNCTION__, packet->m_nBodySize);
	//LogHex(packet.m_body, packet.m_nBodySize);

	// some DEBUG code
	/*RTMP_LIB_AMFObject obj;
	   int nRes = obj.Decode(packet.m_body+1, packet.m_nBodySize-1);
	   if(nRes < 0) {
	   Log(LOGERROR, "%s, error decoding AMF3 packet", __FUNCTION__);
	   //return;
	   }

	   obj.Dump(); */

	if (HandleInvoke(r, packet->m_body + 1, packet->m_nBodySize - 1) == 1)
	  bHasMediaPacket = 2;
	break;
      }
    case 0x12:
      // metadata (notify)
      Log(LOGDEBUG, "%s, received: notify %lu bytes", __FUNCTION__,
	  packet->m_nBodySize);
      if (HandleMetadata(r, packet->m_body, packet->m_nBodySize))
	bHasMediaPacket = 1;
      break;

    case 0x13:
      Log(LOGDEBUG, "%s, shared object, not supported, ignoring",
	  __FUNCTION__);
      break;

    case 0x14:
      // invoke
      Log(LOGDEBUG, "%s, received: invoke %lu bytes", __FUNCTION__,
	  packet->m_nBodySize);
      //LogHex(packet.m_body, packet.m_nBodySize);

      if (HandleInvoke(r, packet->m_body, packet->m_nBodySize) == 1)
	bHasMediaPacket = 2;
      break;

    case 0x16:
      {
	// go through FLV packets and handle metadata packets
	unsigned int pos = 0;
	uint32_t nTimeStamp = packet->m_nTimeStamp;

	while (pos + 11 < packet->m_nBodySize)
	  {
	    uint32_t dataSize = AMF_DecodeInt24(packet->m_body + pos + 1);	// size without header (11) and prevTagSize (4)

	    if (pos + 11 + dataSize + 4 > packet->m_nBodySize)
	      {
		Log(LOGWARNING, "Stream corrupt?!");
		break;
	      }
	    if (packet->m_body[pos] == 0x12)
	      {
		HandleMetadata(r, packet->m_body + pos + 11, dataSize);
	      }
	    else if (packet->m_body[pos] == 8 || packet->m_body[pos] == 9)
	      {
		nTimeStamp = AMF_DecodeInt24(packet->m_body + pos + 4);
		nTimeStamp |= (packet->m_body[pos + 7] << 24);
	      }
	    pos += (11 + dataSize + 4);
	  }
	if (!r->m_pausing)
	  r->m_mediaStamp = nTimeStamp;

	// FLV tag(s)
	//Log(LOGDEBUG, "%s, received: FLV tag(s) %lu bytes", __FUNCTION__, packet.m_nBodySize);
	bHasMediaPacket = 1;
	break;
      }
    default:
      Log(LOGDEBUG, "%s, unknown packet type received: 0x%02x", __FUNCTION__,
	  packet->m_packetType);
#ifdef _DEBUG
      LogHex(LOGDEBUG, packet->m_body, packet->m_nBodySize);
#endif
    }

  return bHasMediaPacket;
}

#ifdef _DEBUG
extern FILE *netstackdump;
extern FILE *netstackdump_read;
#endif

static int
ReadN(RTMP *r, char *buffer, int n)
{
  int nOriginalSize = n;
  char *ptr;

  r->m_sb.sb_timedout = false;

#ifdef _DEBUG
  memset(buffer, 0, n);
#endif

  ptr = buffer;
  while (n > 0)
    {
      int nBytes = 0, nRead;
      if (r->m_sb.sb_size == 0)
	if (RTMPSockBuf_Fill(&r->m_sb) < 1)
	  {
	    if (!r->m_sb.sb_timedout)
	      RTMP_Close(r);
	    return 0;
	  }
      nRead = ((n < r->m_sb.sb_size) ? n : r->m_sb.sb_size);
      if (nRead > 0)
	{
	  memcpy(ptr, r->m_sb.sb_start, nRead);
	  r->m_sb.sb_start += nRead;
	  r->m_sb.sb_size -= nRead;
	  nBytes = nRead;
	  r->m_nBytesIn += nRead;
	  if (r->m_bSendCounter
	      && r->m_nBytesIn > r->m_nBytesInSent + r->m_nClientBW / 2)
	    SendBytesReceived(r);
	}

      //Log(LOGDEBUG, "%s: %d bytes\n", __FUNCTION__, nBytes);
#ifdef _DEBUG
      fwrite(ptr, 1, nBytes, netstackdump_read);
#endif

      if (nBytes == 0)
	{
	  Log(LOGDEBUG, "%s, RTMP socket closed by peer", __FUNCTION__);
	  //goto again;
	  RTMP_Close(r);
	  break;
	}

#ifdef CRYPTO
      if (r->Link.rc4keyIn)
	{
	  RC4(r->Link.rc4keyIn, nBytes, (uint8_t *) ptr, (uint8_t *) ptr);
	}
#endif

      n -= nBytes;
      ptr += nBytes;
    }

  return nOriginalSize - n;
}

static bool
WriteN(RTMP *r, const char *buffer, int n)
{
  const char *ptr = buffer;
#ifdef CRYPTO
  char *encrypted = 0;
  char buf[RTMP_BUFFER_CACHE_SIZE];

  if (r->Link.rc4keyOut)
    {
      if (n > sizeof(buf))
	encrypted = (char *)malloc(n);
      else
	encrypted = (char *)buf;
      ptr = encrypted;
      RC4(r->Link.rc4keyOut, n, (uint8_t *) buffer, (uint8_t *) ptr);
    }
#endif

  while (n > 0)
    {
      int nBytes = RTMPSockBuf_Send(&r->m_sb, ptr, n);
      //Log(LOGDEBUG, "%s: %d\n", __FUNCTION__, nBytes);

      if (nBytes < 0)
	{
	  int sockerr = GetSockError();
	  Log(LOGERROR, "%s, RTMP send error %d (%d bytes)", __FUNCTION__,
	      sockerr, n);

	  if (sockerr == EINTR && !RTMP_ctrlC)
	    continue;

	  RTMP_Close(r);
	  n = 1;
	  break;
	}

      if (nBytes == 0)
	break;

      n -= nBytes;
      ptr += nBytes;
    }

#ifdef CRYPTO
  if (encrypted && encrypted != buf)
    free(encrypted);
#endif

  return n == 0;
}

#define SAVC(x)	static const AVal av_##x = AVC(#x)

SAVC(app);
SAVC(connect);
SAVC(flashVer);
SAVC(swfUrl);
SAVC(pageUrl);
SAVC(tcUrl);
SAVC(fpad);
SAVC(capabilities);
SAVC(audioCodecs);
SAVC(videoCodecs);
SAVC(videoFunction);
SAVC(objectEncoding);
SAVC(secureToken);
SAVC(secureTokenResponse);

static bool
SendConnectPacket(RTMP *r, RTMPPacket *cp)
{
  RTMPPacket packet;
  char pbuf[4096], *pend = pbuf + sizeof(pbuf);

  if (cp)
    return RTMP_SendPacket(r, cp, true);

  packet.m_nChannel = 0x03;	// control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = 0x14;	// INVOKE
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_connect);
  enc = AMF_EncodeNumber(enc, pend, 1.0);
  *enc++ = AMF_OBJECT;

  if (r->Link.app.av_len)
    {
      enc = AMF_EncodeNamedString(enc, pend, &av_app, &r->Link.app);
      if (!enc)
	return false;
    }
  if (r->Link.flashVer.av_len)
    {
      enc = AMF_EncodeNamedString(enc, pend, &av_flashVer, &r->Link.flashVer);
      if (!enc)
	return false;
    }
  if (r->Link.swfUrl.av_len)
    {
      enc = AMF_EncodeNamedString(enc, pend, &av_swfUrl, &r->Link.swfUrl);
      if (!enc)
	return false;
    }
  if (r->Link.tcUrl.av_len)
    {
      enc = AMF_EncodeNamedString(enc, pend, &av_tcUrl, &r->Link.tcUrl);
      if (!enc)
	return false;
    }
  enc = AMF_EncodeNamedBoolean(enc, pend, &av_fpad, false);
  if (!enc)
    return false;
  enc = AMF_EncodeNamedNumber(enc, pend, &av_capabilities, 15.0);
  if (!enc)
    return false;
  enc = AMF_EncodeNamedNumber(enc, pend, &av_audioCodecs, r->m_fAudioCodecs);
  if (!enc)
    return false;
  enc = AMF_EncodeNamedNumber(enc, pend, &av_videoCodecs, r->m_fVideoCodecs);
  if (!enc)
    return false;
  enc = AMF_EncodeNamedNumber(enc, pend, &av_videoFunction, 1.0);
  if (!enc)
    return false;
  if (r->Link.pageUrl.av_len)
    {
      enc = AMF_EncodeNamedString(enc, pend, &av_pageUrl, &r->Link.pageUrl);
      if (!enc)
	return false;
    }
  if (r->m_fEncoding != 0.0 || r->m_bSendEncoding)
    {
      enc = AMF_EncodeNamedNumber(enc, pend, &av_objectEncoding, r->m_fEncoding);	// AMF0, AMF3 not supported yet
      if (!enc)
	return false;
    }
  if (enc + 3 >= pend)
    return false;
  *enc++ = 0;
  *enc++ = 0;			// end of object - 0x00 0x00 0x09
  *enc++ = AMF_OBJECT_END;

  // add auth string
  if (r->Link.auth.av_len)
    {
      enc = AMF_EncodeBoolean(enc, pend, r->Link.authflag);
      if (!enc)
	return false;
      enc = AMF_EncodeString(enc, pend, &r->Link.auth);
      if (!enc)
	return false;
    }
  if (r->Link.extras.o_num)
    {
      int i;
      for (i = 0; i < r->Link.extras.o_num; i++)
	{
	  enc = AMFProp_Encode(&r->Link.extras.o_props[i], enc, pend);
	  if (!enc)
	    return false;
	}
    }
  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, true);
}

#if 0				/* unused */
SAVC(bgHasStream);

static bool
SendBGHasStream(RTMP *r, double dId, AVal *playpath)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;	// control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x14;	// INVOKE
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_bgHasStream);
  enc = AMF_EncodeNumber(enc, pend, dId);
  *enc++ = AMF_NULL;

  enc = AMF_EncodeString(enc, pend, playpath);
  if (enc == NULL)
    return false;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, true);
}
#endif

SAVC(createStream);

bool
RTMP_SendCreateStream(RTMP *r, double dCmdID)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;	// control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x14;	// INVOKE
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_createStream);
  enc = AMF_EncodeNumber(enc, pend, dCmdID);
  *enc++ = AMF_NULL;		// NULL

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, true);
}

SAVC(FCSubscribe);

static bool
SendFCSubscribe(RTMP *r, AVal *subscribepath)
{
  RTMPPacket packet;
  char pbuf[512], *pend = pbuf + sizeof(pbuf);
  packet.m_nChannel = 0x03;	// control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x14;	// INVOKE
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  Log(LOGDEBUG, "FCSubscribe: %s", subscribepath->av_val);
  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_FCSubscribe);
  enc = AMF_EncodeNumber(enc, pend, 4.0);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeString(enc, pend, subscribepath);

  if (!enc)
    return false;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, true);
}

SAVC(deleteStream);

static bool
SendDeleteStream(RTMP *r, double dStreamId)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;	// control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x14;	// INVOKE
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_deleteStream);
  enc = AMF_EncodeNumber(enc, pend, 0.0);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeNumber(enc, pend, dStreamId);

  packet.m_nBodySize = enc - packet.m_body;

  /* no response expected */
  return RTMP_SendPacket(r, &packet, false);
}

SAVC(pause);

bool
RTMP_SendPause(RTMP *r, bool DoPause, double dTime)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x08;	// video channel
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x14;	// invoke
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_pause);
  enc = AMF_EncodeNumber(enc, pend, 0);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeBoolean(enc, pend, DoPause);
  enc = AMF_EncodeNumber(enc, pend, (double)dTime);

  packet.m_nBodySize = enc - packet.m_body;

  Log(LOGDEBUG, "%s, %d, pauseTime=%.2f", __FUNCTION__, DoPause, dTime);
  return RTMP_SendPacket(r, &packet, true);
}

SAVC(seek);

bool
RTMP_SendSeek(RTMP *r, double dTime)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x08;	// video channel
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x14;	// invoke
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_seek);
  enc = AMF_EncodeNumber(enc, pend, 0);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeNumber(enc, pend, dTime);

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, true);
}

bool
RTMP_SendServerBW(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x02;	// control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = 0x05;	// Server BW
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  packet.m_nBodySize = 4;

  AMF_EncodeInt32(packet.m_body, pend, r->m_nServerBW);
  return RTMP_SendPacket(r, &packet, false);
}

static bool
SendBytesReceived(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x02;	// control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x03;	// bytes in
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  packet.m_nBodySize = 4;

  AMF_EncodeInt32(packet.m_body, pend, r->m_nBytesIn);	// hard coded for now
  r->m_nBytesInSent = r->m_nBytesIn;

  //Log(LOGDEBUG, "Send bytes report. 0x%x (%d bytes)", (unsigned int)m_nBytesIn, m_nBytesIn);
  return RTMP_SendPacket(r, &packet, false);
}

SAVC(_checkbw);

static bool
SendCheckBW(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;	// control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = 0x14;	// INVOKE
  packet.m_nInfoField1 = 0;	/* RTMP_GetTime(); */
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__checkbw);
  enc = AMF_EncodeNumber(enc, pend, 0);
  *enc++ = AMF_NULL;

  packet.m_nBodySize = enc - packet.m_body;

  // triggers _onbwcheck and eventually results in _onbwdone
  return RTMP_SendPacket(r, &packet, false);
}

SAVC(_result);

static bool
SendCheckBWResult(RTMP *r, double txn)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;	// control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x14;	// INVOKE
  packet.m_nInfoField1 = 0x16 * r->m_nBWCheckCounter;	// temp inc value. till we figure it out.
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeNumber(enc, pend, (double)r->m_nBWCheckCounter++);

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, false);
}

SAVC(play);

static bool
SendPlay(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x08;	// we make 8 our stream channel
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = 0x14;	// INVOKE
  packet.m_nInfoField2 = r->m_stream_id;	//0x01000000;
  packet.m_nInfoField1 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_play);
  enc = AMF_EncodeNumber(enc, pend, 0.0);	// stream id??
  *enc++ = AMF_NULL;

  Log(LOGDEBUG, "%s, seekTime=%.2f, dLength=%d, sending play: %s",
      __FUNCTION__, r->Link.seekTime, r->Link.length,
      r->Link.playpath.av_val);
  enc = AMF_EncodeString(enc, pend, &r->Link.playpath);
  if (!enc)
    return false;

  // Optional parameters start and len.

  // start: -2, -1, 0, positive number
  //  -2: looks for a live stream, then a recorded stream, if not found any open a live stream
  //  -1: plays a live stream
  // >=0: plays a recorded streams from 'start' milliseconds
  if (r->Link.bLiveStream)
    enc = AMF_EncodeNumber(enc, pend, -1000.0);
  else
    {
      if (r->Link.seekTime > 0.0)
	enc = AMF_EncodeNumber(enc, pend, r->Link.seekTime);	// resume from here
      else
	enc = AMF_EncodeNumber(enc, pend, 0.0);	//-2000.0); // recorded as default, -2000.0 is not reliable since that freezes the player if the stream is not found
    }
  if (!enc)
    return false;

  // len: -1, 0, positive number
  //  -1: plays live or recorded stream to the end (default)
  //   0: plays a frame 'start' ms away from the beginning
  //  >0: plays a live or recoded stream for 'len' milliseconds
  //enc += EncodeNumber(enc, -1.0); // len
  if (r->Link.length)
    {
      enc = AMF_EncodeNumber(enc, pend, r->Link.length);	// len
      if (!enc)
	return false;
    }

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, true);
}

static bool
SendSecureTokenResponse(RTMP *r, AVal *resp)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x14;
  packet.m_nInfoField2 = 0;
  packet.m_nInfoField1 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_secureTokenResponse);
  enc = AMF_EncodeNumber(enc, pend, 0.0);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeString(enc, pend, resp);
  if (!enc)
    return false;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, false);
}

/*
from http://jira.red5.org/confluence/display/docs/Ping:

Ping is the most mysterious message in RTMP and till now we haven't fully interpreted it yet. In summary, Ping message is used as a special command that are exchanged between client and server. This page aims to document all known Ping messages. Expect the list to grow.

The type of Ping packet is 0x4 and contains two mandatory parameters and two optional parameters. The first parameter is the type of Ping and in short integer. The second parameter is the target of the ping. As Ping is always sent in Channel 2 (control channel) and the target object in RTMP header is always 0 which means the Connection object, it's necessary to put an extra parameter to indicate the exact target object the Ping is sent to. The second parameter takes this responsibility. The value has the same meaning as the target object field in RTMP header. (The second value could also be used as other purposes, like RTT Ping/Pong. It is used as the timestamp.) The third and fourth parameters are optional and could be looked upon as the parameter of the Ping packet. Below is an unexhausted list of Ping messages.

    * type 0: Clear the stream. No third and fourth parameters. The second parameter could be 0. After the connection is established, a Ping 0,0 will be sent from server to client. The message will also be sent to client on the start of Play and in response of a Seek or Pause/Resume request. This Ping tells client to re-calibrate the clock with the timestamp of the next packet server sends.
    * type 1: Tell the stream to clear the playing buffer.
    * type 3: Buffer time of the client. The third parameter is the buffer time in millisecond.
    * type 4: Reset a stream. Used together with type 0 in the case of VOD. Often sent before type 0.
    * type 6: Ping the client from server. The second parameter is the current time.
    * type 7: Pong reply from client. The second parameter is the time the server sent with his ping request.
    * type 26: SWFVerification request
    * type 27: SWFVerification response
*/
bool
RTMP_SendCtrl(RTMP *r, short nType, unsigned int nObject, unsigned int nTime)
{
  Log(LOGDEBUG, "sending ctrl. type: 0x%04x", (unsigned short)nType);

  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x02;	// control channel (ping)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = 0x04;	// ctrl
  packet.m_nInfoField1 = 0;	/* RTMP_GetTime(); */
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  int nSize = (nType == 0x03 ? 10 : 6);	// type 3 is the buffer time and requires all 3 parameters. all in all 10 bytes.
  if (nType == 0x1B)
    nSize = 44;

  packet.m_nBodySize = nSize;

  char *buf = packet.m_body;
  buf = AMF_EncodeInt16(buf, pend, nType);

  if (nType == 0x1B)
    {
#ifdef CRYPTO
      memcpy(buf, r->Link.SWFVerificationResponse, 42);
      Log(LOGDEBUG, "Sending SWFVerification response: ");
      LogHex(LOGDEBUG, packet.m_body, packet.m_nBodySize);
#endif
    }
  else
    {
      if (nSize > 2)
	buf = AMF_EncodeInt32(buf, pend, nObject);

      if (nSize > 6)
	buf = AMF_EncodeInt32(buf, pend, nTime);
    }

  return RTMP_SendPacket(r, &packet, false);
}

static void
AV_erase(AVal *vals, int *num, int i, bool freeit)
{
  if (freeit)
    free(vals[i].av_val);
  (*num)--;
  for (; i < *num; i++)
    {
      vals[i] = vals[i + 1];
    }
  vals[i].av_val = NULL;
  vals[i].av_len = 0;
}

void
RTMP_DropRequest(RTMP *r, int i, bool freeit)
{
  AV_erase(r->m_methodCalls, &r->m_numCalls, i, freeit);
}

static void
AV_queue(AVal **vals, int *num, AVal *av)
{
  char *tmp;
  if (!(*num & 0x0f))
    *vals = realloc(*vals, (*num + 16) * sizeof(AVal));
  tmp = malloc(av->av_len + 1);
  memcpy(tmp, av->av_val, av->av_len);
  tmp[av->av_len] = '\0';
  (*vals)[*num].av_len = av->av_len;
  (*vals)[(*num)++].av_val = tmp;
}

static void
AV_clear(AVal *vals, int num)
{
  int i;
  for (i = 0; i < num; i++)
    free(vals[i].av_val);
  free(vals);
}

SAVC(onBWDone);
SAVC(onFCSubscribe);
SAVC(onFCUnsubscribe);
SAVC(_onbwcheck);
SAVC(_onbwdone);
SAVC(_error);
SAVC(close);
SAVC(code);
SAVC(level);
SAVC(onStatus);
static const AVal av_NetStream_Failed = AVC("NetStream.Failed");
static const AVal av_NetStream_Play_Failed = AVC("NetStream.Play.Failed");
static const AVal av_NetStream_Play_StreamNotFound =
AVC("NetStream.Play.StreamNotFound");
static const AVal av_NetConnection_Connect_InvalidApp =
AVC("NetConnection.Connect.InvalidApp");
static const AVal av_NetStream_Play_Start = AVC("NetStream.Play.Start");
static const AVal av_NetStream_Play_Complete = AVC("NetStream.Play.Complete");
static const AVal av_NetStream_Play_Stop = AVC("NetStream.Play.Stop");

// Returns 0 for OK/Failed/error, 1 for 'Stop or Complete'
static int
HandleInvoke(RTMP *r, const char *body, unsigned int nBodySize)
{
  int ret = 0, nRes;
  if (body[0] != 0x02)		// make sure it is a string method name we start with
    {
      Log(LOGWARNING, "%s, Sanity failed. no string method in invoke packet",
	  __FUNCTION__);
      return 0;
    }

  AMFObject obj;
  nRes = AMF_Decode(&obj, body, nBodySize, false);
  if (nRes < 0)
    {
      Log(LOGERROR, "%s, error decoding invoke packet", __FUNCTION__);
      return 0;
    }

  AMF_Dump(&obj);
  AVal method;
  AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &method);
  double txn = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 1));
  Log(LOGDEBUG, "%s, server invoking <%s>", __FUNCTION__, method.av_val);

  if (AVMATCH(&method, &av__result))
    {
      AVal methodInvoked = r->m_methodCalls[0];
      AV_erase(r->m_methodCalls, &r->m_numCalls, 0, false);

      Log(LOGDEBUG, "%s, received result for method call <%s>", __FUNCTION__,
	  methodInvoked.av_val);

      if (AVMATCH(&methodInvoked, &av_connect))
	{
	  if (r->Link.token.av_len)
	    {
	      AMFObjectProperty p;
	      if (RTMP_FindFirstMatchingProperty(&obj, &av_secureToken, &p))
		{
		  DecodeTEA(&r->Link.token, &p.p_vu.p_aval);
		  SendSecureTokenResponse(r, &p.p_vu.p_aval);
		}
	    }
	  RTMP_SendServerBW(r);
	  RTMP_SendCtrl(r, 3, 0, 300);

	  RTMP_SendCreateStream(r, 2.0);

	  /* Send the FCSubscribe if live stream or if subscribepath is set */
	  if (r->Link.subscribepath.av_len)
	    SendFCSubscribe(r, &r->Link.subscribepath);
	  else if (r->Link.bLiveStream)
	    SendFCSubscribe(r, &r->Link.playpath);
	}
      else if (AVMATCH(&methodInvoked, &av_createStream))
	{
	  r->m_stream_id = (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 3));

	  SendPlay(r);
	  RTMP_SendCtrl(r, 3, r->m_stream_id, r->m_nBufferMS);
	}
      else if (AVMATCH(&methodInvoked, &av_play))
	{
	  r->m_bPlaying = true;
	}
      free(methodInvoked.av_val);
    }
  else if (AVMATCH(&method, &av_onBWDone))
    {
      SendCheckBW(r);
    }
  else if (AVMATCH(&method, &av_onFCSubscribe))
    {
      // SendOnFCSubscribe();
    }
  else if (AVMATCH(&method, &av_onFCUnsubscribe))
    {
      RTMP_Close(r);
      ret = 1;
    }
  else if (AVMATCH(&method, &av__onbwcheck))
    {
      SendCheckBWResult(r, txn);
    }
  else if (AVMATCH(&method, &av__onbwdone))
    {
      int i;
      for (i = 0; i < r->m_numCalls; i++)
	if (AVMATCH(&r->m_methodCalls[i], &av__checkbw))
	  {
	    AV_erase(r->m_methodCalls, &r->m_numCalls, i, true);
	    break;
	  }
    }
  else if (AVMATCH(&method, &av__error))
    {
      Log(LOGERROR, "rtmp server sent error");
    }
  else if (AVMATCH(&method, &av_close))
    {
      Log(LOGERROR, "rtmp server requested close");
      RTMP_Close(r);
    }
  else if (AVMATCH(&method, &av_onStatus))
    {
      AMFObject obj2;
      AVal code, level;
      AMFProp_GetObject(AMF_GetProp(&obj, NULL, 3), &obj2);
      AMFProp_GetString(AMF_GetProp(&obj2, &av_code, -1), &code);
      AMFProp_GetString(AMF_GetProp(&obj2, &av_level, -1), &level);

      Log(LOGDEBUG, "%s, onStatus: %s", __FUNCTION__, code.av_val);
      if (AVMATCH(&code, &av_NetStream_Failed)
	  || AVMATCH(&code, &av_NetStream_Play_Failed)
	  || AVMATCH(&code, &av_NetStream_Play_StreamNotFound)
	  || AVMATCH(&code, &av_NetConnection_Connect_InvalidApp))
	{
	  r->m_stream_id = -1;
	  RTMP_Close(r);
	  Log(LOGERROR, "Closing connection: %s", code.av_val);
	}

      if (AVMATCH(&code, &av_NetStream_Play_Start))
	{
	  int i;
	  r->m_bPlaying = true;
	  for (i = 0; i < r->m_numCalls; i++)
	    {
	      if (AVMATCH(&r->m_methodCalls[i], &av_play))
		{
		  AV_erase(r->m_methodCalls, &r->m_numCalls, i, true);
		  break;
		}
	    }
	}

      // Return 1 if this is a Play.Complete or Play.Stop
      if (AVMATCH(&code, &av_NetStream_Play_Complete)
	  || AVMATCH(&code, &av_NetStream_Play_Stop))
	{
	  RTMP_Close(r);
	  ret = 1;
	}
    }
  else
    {

    }
  AMF_Reset(&obj);
  return ret;
}

bool
RTMP_FindFirstMatchingProperty(AMFObject *obj, const AVal *name,
			       AMFObjectProperty * p)
{
  int n;
  /* this is a small object search to locate the "duration" property */
  for (n = 0; n < obj->o_num; n++)
    {
      AMFObjectProperty *prop = AMF_GetProp(obj, NULL, n);

      if (AVMATCH(&prop->p_name, name))
	{
	  *p = *prop;
	  return true;
	}

      if (prop->p_type == AMF_OBJECT)
	{
	  if (RTMP_FindFirstMatchingProperty(&prop->p_vu.p_object, name, p))
	    return true;
	}
    }
  return false;
}

static bool
DumpMetaData(AMFObject *obj)
{
  AMFObjectProperty *prop;
  int n;
  for (n = 0; n < obj->o_num; n++)
    {
      prop = AMF_GetProp(obj, NULL, n);
      if (prop->p_type != AMF_OBJECT)
	{
	  char str[256] = "";
	  switch (prop->p_type)
	    {
	    case AMF_NUMBER:
	      snprintf(str, 255, "%.2f", prop->p_vu.p_number);
	      break;
	    case AMF_BOOLEAN:
	      snprintf(str, 255, "%s",
		       prop->p_vu.p_number != 0. ? "TRUE" : "FALSE");
	      break;
	    case AMF_STRING:
	      snprintf(str, 255, "%.*s", prop->p_vu.p_aval.av_len,
		       prop->p_vu.p_aval.av_val);
	      break;
	    case AMF_DATE:
	      snprintf(str, 255, "timestamp:%.2f", prop->p_vu.p_number);
	      break;
	    default:
	      snprintf(str, 255, "INVALID TYPE 0x%02x",
		       (unsigned char)prop->p_type);
	    }
	  if (prop->p_name.av_len)
	    {
	      // chomp
	      if (strlen(str) >= 1 && str[strlen(str) - 1] == '\n')
		str[strlen(str) - 1] = '\0';
	      LogPrintf("  %-22.*s%s\n", prop->p_name.av_len,
			prop->p_name.av_val, str);
	    }
	}
      else
	{
	  if (prop->p_name.av_len)
	    LogPrintf("%.*s:\n", prop->p_name.av_len, prop->p_name.av_val);
	  DumpMetaData(&prop->p_vu.p_object);
	}
    }
  return false;
}

SAVC(onMetaData);
SAVC(duration);

static bool
HandleMetadata(RTMP *r, char *body, unsigned int len)
{
  // allright we get some info here, so parse it and print it
  // also keep duration or filesize to make a nice progress bar

  AMFObject obj;
  AVal metastring;
  bool ret = false;

  int nRes = AMF_Decode(&obj, body, len, false);
  if (nRes < 0)
    {
      Log(LOGERROR, "%s, error decoding meta data packet", __FUNCTION__);
      return false;
    }

  AMF_Dump(&obj);
  AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &metastring);

  if (AVMATCH(&metastring, &av_onMetaData))
    {
      AMFObjectProperty prop;
      // Show metadata
      LogPrintf("Metadata:\n");
      DumpMetaData(&obj);
      if (RTMP_FindFirstMatchingProperty(&obj, &av_duration, &prop))
	{
	  r->m_fDuration = prop.p_vu.p_number;
	  //Log(LOGDEBUG, "Set duration: %.2f", m_fDuration);
	}
      ret = true;
    }
  AMF_Reset(&obj);
  return ret;
}

static void
HandleChangeChunkSize(RTMP *r, const RTMPPacket *packet)
{
  if (packet->m_nBodySize >= 4)
    {
      r->m_inChunkSize = AMF_DecodeInt32(packet->m_body);
      Log(LOGDEBUG, "%s, received: chunk size change to %d", __FUNCTION__,
	  r->m_inChunkSize);
    }
}

static void
HandleAudio(RTMP *r, const RTMPPacket *packet)
{
}

static void
HandleVideo(RTMP *r, const RTMPPacket *packet)
{
}

static void
HandleCtrl(RTMP *r, const RTMPPacket *packet)
{
  short nType = -1;
  unsigned int tmp;
  if (packet->m_body && packet->m_nBodySize >= 2)
    nType = AMF_DecodeInt16(packet->m_body);
  Log(LOGDEBUG, "%s, received ctrl. type: %d, len: %d", __FUNCTION__, nType,
      packet->m_nBodySize);
  //LogHex(packet.m_body, packet.m_nBodySize);

  if (packet->m_nBodySize >= 6)
    {
      switch (nType)
	{
	case 0:
	  tmp = AMF_DecodeInt32(packet->m_body + 2);
	  Log(LOGDEBUG, "%s, Stream Begin %d", __FUNCTION__, tmp);
	  break;

	case 1:
	  tmp = AMF_DecodeInt32(packet->m_body + 2);
	  Log(LOGDEBUG, "%s, Stream EOF %d", __FUNCTION__, tmp);
	  if (r->m_pausing == 1)
	    r->m_pausing = 2;
	  break;

	case 2:
	  tmp = AMF_DecodeInt32(packet->m_body + 2);
	  Log(LOGDEBUG, "%s, Stream Dry %d", __FUNCTION__, tmp);
	  break;

	case 4:
	  tmp = AMF_DecodeInt32(packet->m_body + 2);
	  Log(LOGDEBUG, "%s, Stream IsRecorded %d", __FUNCTION__, tmp);
	  break;

	case 6:		// server ping. reply with pong.
	  tmp = AMF_DecodeInt32(packet->m_body + 2);
	  Log(LOGDEBUG, "%s, Ping %d", __FUNCTION__, tmp);
	  RTMP_SendCtrl(r, 0x07, tmp, 0);
	  break;

	case 31:
	  tmp = AMF_DecodeInt32(packet->m_body + 2);
	  Log(LOGDEBUG, "%s, Stream BufferEmpty %d", __FUNCTION__, tmp);
	  if (r->Link.bLiveStream)
	    break;
	  if (!r->m_pausing)
	    {
	      r->m_pauseStamp = r->m_channelTimestamp[r->m_mediaChannel];
	      RTMP_SendPause(r, true, r->m_pauseStamp);
	      r->m_pausing = 1;
	    }
	  else if (r->m_pausing == 2)
	    {
	      RTMP_SendPause(r, false, r->m_pauseStamp);
	      r->m_pausing = 3;
	    }
	  break;

	case 32:
	  tmp = AMF_DecodeInt32(packet->m_body + 2);
	  Log(LOGDEBUG, "%s, Stream BufferReady %d", __FUNCTION__, tmp);
	  break;

	default:
	  tmp = AMF_DecodeInt32(packet->m_body + 2);
	  Log(LOGDEBUG, "%s, Stream xx %d", __FUNCTION__, tmp);
	  break;
	}

    }

  if (nType == 0x1A)
    {
      Log(LOGDEBUG, "%s, SWFVerification ping received: ", __FUNCTION__);
#ifdef CRYPTO
      //LogHex(packet.m_body, packet.m_nBodySize);

      // respond with HMAC SHA256 of decompressed SWF, key is the 30byte player key, also the last 30 bytes of the server handshake are applied
      if (r->Link.SWFHash.av_len)
	{
	  RTMP_SendCtrl(r, 0x1B, 0, 0);
	}
      else
	{
	  Log(LOGERROR,
	      "%s: Ignoring SWFVerification request, use --swfVfy!",
	      __FUNCTION__);
	}
#else
      Log(LOGERROR,
	  "%s: Ignoring SWFVerification request, no CRYPTO support!",
	  __FUNCTION__);
#endif
    }
}

static void
HandleServerBW(RTMP *r, const RTMPPacket *packet)
{
  r->m_nServerBW = AMF_DecodeInt32(packet->m_body);
  Log(LOGDEBUG, "%s: server BW = %d", __FUNCTION__, r->m_nServerBW);
}

static void
HandleClientBW(RTMP *r, const RTMPPacket *packet)
{
  r->m_nClientBW = AMF_DecodeInt32(packet->m_body);
  if (packet->m_nBodySize > 4)
    r->m_nClientBW2 = packet->m_body[4];
  else
    r->m_nClientBW2 = -1;
  Log(LOGDEBUG, "%s: client BW = %d %d", __FUNCTION__, r->m_nClientBW,
      r->m_nClientBW2);
}

static int
DecodeInt32LE(const char *data)
{
  unsigned char *c = (unsigned char *)data;
  unsigned int val;

  val = (c[3] << 24) | (c[2] << 16) | (c[1] << 8) | c[0];
  return val;
}

static int
EncodeInt32LE(char *output, int nVal)
{
  output[0] = nVal;
  nVal >>= 8;
  output[1] = nVal;
  nVal >>= 8;
  output[2] = nVal;
  nVal >>= 8;
  output[3] = nVal;
  return 4;
}

bool
RTMP_ReadPacket(RTMP *r, RTMPPacket *packet)
{
  char hbuf[RTMP_MAX_HEADER_SIZE] = { 0 }, *header = hbuf;

  Log(LOGDEBUG2, "%s: fd=%d", __FUNCTION__, r->m_sb.sb_socket);

  if (ReadN(r, hbuf, 1) == 0)
    {
      Log(LOGERROR, "%s, failed to read RTMP packet header", __FUNCTION__);
      return false;
    }

  packet->m_headerType = (hbuf[0] & 0xc0) >> 6;
  packet->m_nChannel = (hbuf[0] & 0x3f);
  header++;
  if (packet->m_nChannel == 0)
    {
      if (ReadN(r, &hbuf[1], 1) != 1)
	{
	  Log(LOGERROR, "%s, failed to read RTMP packet header 2nd byte",
	      __FUNCTION__);
	  return false;
	}
      packet->m_nChannel = (unsigned)hbuf[1];
      packet->m_nChannel += 64;
      header++;
    }
  else if (packet->m_nChannel == 1)
    {
      int tmp;
      if (ReadN(r, &hbuf[1], 2) != 2)
	{
	  Log(LOGERROR, "%s, failed to read RTMP packet header 3nd byte",
	      __FUNCTION__);
	  return false;
	}
      tmp = (((unsigned)hbuf[2]) << 8) + (unsigned)hbuf[1];
      packet->m_nChannel = tmp + 64;
      Log(LOGDEBUG, "%s, m_nChannel: %0x", __FUNCTION__, packet->m_nChannel);
      header += 2;
    }

  int nSize = packetSize[packet->m_headerType], hSize;

  if (nSize == RTMP_LARGE_HEADER_SIZE)	// if we get a full header the timestamp is absolute
    packet->m_hasAbsTimestamp = true;

  else if (nSize < RTMP_LARGE_HEADER_SIZE)
    {				// using values from the last message of this channel
      if (r->m_vecChannelsIn[packet->m_nChannel])
	memcpy(packet, r->m_vecChannelsIn[packet->m_nChannel],
	       sizeof(RTMPPacket));
    }

  nSize--;

  if (nSize > 0 && ReadN(r, header, nSize) != nSize)
    {
      Log(LOGERROR, "%s, failed to read RTMP packet header. type: %x",
	  __FUNCTION__, (unsigned int)hbuf[0]);
      return false;
    }

  hSize = nSize + (header - hbuf);

  if (nSize >= 3)
    {
      packet->m_nInfoField1 = AMF_DecodeInt24(header);

      //Log(LOGDEBUG, "%s, reading RTMP packet chunk on channel %x, headersz %i, timestamp %i, abs timestamp %i", __FUNCTION__, packet.m_nChannel, nSize, packet.m_nInfoField1, packet.m_hasAbsTimestamp);

      if (nSize >= 6)
	{
	  packet->m_nBodySize = AMF_DecodeInt24(header + 3);
	  packet->m_nBytesRead = 0;
	  RTMPPacket_Free(packet);

	  if (nSize > 6)
	    {
	      packet->m_packetType = header[6];

	      if (nSize == 11)
		packet->m_nInfoField2 = DecodeInt32LE(header + 7);
	    }
	}
      if (packet->m_nInfoField1 == 0xffffff)
	{
	  if (ReadN(r, header + nSize, 4) != 4)
	    {
	      Log(LOGERROR, "%s, failed to read extended timestamp",
		  __FUNCTION__);
	      return false;
	    }
	  packet->m_nInfoField1 = AMF_DecodeInt32(header + nSize);
	  hSize += 4;
	}
    }

  LogHexString(LOGDEBUG2, hbuf, hSize);

  bool didAlloc = false;
  if (packet->m_nBodySize > 0 && packet->m_body == NULL)
    {
      if (!RTMPPacket_Alloc(packet, packet->m_nBodySize))
	{
	  Log(LOGDEBUG, "%s, failed to allocate packet", __FUNCTION__);
	  return false;
	}
      didAlloc = true;
      packet->m_headerType = (hbuf[0] & 0xc0) >> 6;
    }

  int nToRead = packet->m_nBodySize - packet->m_nBytesRead;
  int nChunk = r->m_inChunkSize;
  if (nToRead < nChunk)
    nChunk = nToRead;

  /* Does the caller want the raw chunk? */
  if (packet->m_chunk)
    {
      packet->m_chunk->c_headerSize = hSize;
      memcpy(packet->m_chunk->c_header, hbuf, hSize);
      packet->m_chunk->c_chunk = packet->m_body + packet->m_nBytesRead;
      packet->m_chunk->c_chunkSize = nChunk;
    }

  if (ReadN(r, packet->m_body + packet->m_nBytesRead, nChunk) != nChunk)
    {
      Log(LOGERROR, "%s, failed to read RTMP packet body. len: %lu",
	  __FUNCTION__, packet->m_nBodySize);
      return false;
    }

  LogHexString(LOGDEBUG2, packet->m_body + packet->m_nBytesRead, nChunk);

  packet->m_nBytesRead += nChunk;

  // keep the packet as ref for other packets on this channel
  if (!r->m_vecChannelsIn[packet->m_nChannel])
    r->m_vecChannelsIn[packet->m_nChannel] = malloc(sizeof(RTMPPacket));
  memcpy(r->m_vecChannelsIn[packet->m_nChannel], packet, sizeof(RTMPPacket));

  if (RTMPPacket_IsReady(packet))
    {
      packet->m_nTimeStamp = packet->m_nInfoField1;

      // make packet's timestamp absolute
      if (!packet->m_hasAbsTimestamp)
	packet->m_nTimeStamp += r->m_channelTimestamp[packet->m_nChannel];	// timestamps seem to be always relative!!

      r->m_channelTimestamp[packet->m_nChannel] = packet->m_nTimeStamp;

      // reset the data from the stored packet. we keep the header since we may use it later if a new packet for this channel
      // arrives and requests to re-use some info (small packet header)
      r->m_vecChannelsIn[packet->m_nChannel]->m_body = NULL;
      r->m_vecChannelsIn[packet->m_nChannel]->m_nBytesRead = 0;
      r->m_vecChannelsIn[packet->m_nChannel]->m_hasAbsTimestamp = false;	// can only be false if we reuse header
    }
  else
    {
      packet->m_body = NULL;	/* so it won't be erased on free */
    }

  return true;
}

#ifdef CRYPTO
#include "handshake.h"
#else
static bool
HandShake(RTMP *r, bool FP9HandShake)
{
  int i;
  char clientbuf[RTMP_SIG_SIZE + 1], *clientsig = clientbuf + 1;
  char serversig[RTMP_SIG_SIZE];

  clientbuf[0] = 0x03;		// not encrypted

  uint32_t uptime = htonl(RTMP_GetTime());
  memcpy(clientsig, &uptime, 4);

  memset(&clientsig[4], 0, 4);

#ifdef _DEBUG
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    clientsig[i] = 0xff;
#else
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    clientsig[i] = (char)(rand() % 256);
#endif

  if (!WriteN(r, clientbuf, RTMP_SIG_SIZE + 1))
    return false;

  char type;
  if (ReadN(r, &type, 1) != 1)	// 0x03 or 0x06
    return false;

  Log(LOGDEBUG, "%s: Type Answer   : %02X", __FUNCTION__, type);

  if (type != clientbuf[0])
    Log(LOGWARNING, "%s: Type mismatch: client sent %d, server answered %d",
	__FUNCTION__, clientbuf[0], type);

  if (ReadN(r, serversig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return false;

  // decode server response
  uint32_t suptime;

  memcpy(&suptime, serversig, 4);
  suptime = ntohl(suptime);

  Log(LOGDEBUG, "%s: Server Uptime : %d", __FUNCTION__, suptime);
  Log(LOGDEBUG, "%s: FMS Version   : %d.%d.%d.%d", __FUNCTION__,
      serversig[4], serversig[5], serversig[6], serversig[7]);

  // 2nd part of handshake
  if (!WriteN(r, serversig, RTMP_SIG_SIZE))
    return false;

  if (ReadN(r, serversig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return false;

  bool bMatch = (memcmp(serversig, clientsig, RTMP_SIG_SIZE) == 0);
  if (!bMatch)
    {
      Log(LOGWARNING, "%s, client signature does not match!", __FUNCTION__);
    }
  return true;
}

static bool
SHandShake(RTMP *r)
{
  int i;
  char serverbuf[RTMP_SIG_SIZE + 1], *serversig = serverbuf + 1;
  char clientsig[RTMP_SIG_SIZE];
  uint32_t uptime;

  if (ReadN(r, serverbuf, 1) != 1)	// 0x03 or 0x06
    return false;

  Log(LOGDEBUG, "%s: Type Request  : %02X", __FUNCTION__, serverbuf[0]);

  if (serverbuf[0] != 3)
    {
      Log(LOGERROR, "%s: Type unknown: client sent %02X",
	  __FUNCTION__, serverbuf[0]);
      return false;
    }

  uptime = htonl(RTMP_GetTime());
  memcpy(serversig, &uptime, 4);

  memset(&serversig[4], 0, 4);
#ifdef _DEBUG
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    serversig[i] = 0xff;
#else
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    serversig[i] = (char)(rand() % 256);
#endif

  if (!WriteN(r, serverbuf, RTMP_SIG_SIZE + 1))
    return false;

  if (ReadN(r, clientsig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return false;

  // decode client response

  memcpy(&uptime, clientsig, 4);
  uptime = ntohl(uptime);

  Log(LOGDEBUG, "%s: Client Uptime : %d", __FUNCTION__, uptime);
  Log(LOGDEBUG, "%s: Player Version: %d.%d.%d.%d", __FUNCTION__,
      clientsig[4], clientsig[5], clientsig[6], clientsig[7]);

  // 2nd part of handshake
  if (!WriteN(r, clientsig, RTMP_SIG_SIZE))
    return false;

  if (ReadN(r, clientsig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return false;

  bool bMatch = (memcmp(serversig, clientsig, RTMP_SIG_SIZE) == 0);
  if (!bMatch)
    {
      Log(LOGWARNING, "%s, client signature does not match!", __FUNCTION__);
    }
  return true;
}
#endif

bool
RTMP_SendChunk(RTMP *r, RTMPChunk *chunk)
{
  bool wrote;
  char hbuf[RTMP_MAX_HEADER_SIZE];

  Log(LOGDEBUG2, "%s: fd=%d, size=%d", __FUNCTION__, r->m_sb.sb_socket,
      chunk->c_chunkSize);
  LogHexString(LOGDEBUG2, chunk->c_header, chunk->c_headerSize);
  if (chunk->c_chunkSize)
    {
      char *ptr = chunk->c_chunk - chunk->c_headerSize;
      LogHexString(LOGDEBUG2, chunk->c_chunk, chunk->c_chunkSize);
      /* save header bytes we're about to overwrite */
      memcpy(hbuf, ptr, chunk->c_headerSize);
      memcpy(ptr, chunk->c_header, chunk->c_headerSize);
      wrote = WriteN(r, ptr, chunk->c_headerSize + chunk->c_chunkSize);
      memcpy(ptr, hbuf, chunk->c_headerSize);
    }
  else
    wrote = WriteN(r, chunk->c_header, chunk->c_headerSize);
  return wrote;
}

bool
RTMP_SendPacket(RTMP *r, RTMPPacket *packet, bool queue)
{
  const RTMPPacket *prevPacket = r->m_vecChannelsOut[packet->m_nChannel];
  if (prevPacket && packet->m_headerType != RTMP_PACKET_SIZE_LARGE)
    {
      // compress a bit by using the prev packet's attributes
      if (prevPacket->m_nBodySize == packet->m_nBodySize
	  && packet->m_headerType == RTMP_PACKET_SIZE_MEDIUM)
	packet->m_headerType = RTMP_PACKET_SIZE_SMALL;

      if (prevPacket->m_nInfoField2 == packet->m_nInfoField2
	  && packet->m_headerType == RTMP_PACKET_SIZE_SMALL)
	packet->m_headerType = RTMP_PACKET_SIZE_MINIMUM;

    }

  if (packet->m_headerType > 3)	// sanity
    {
      Log(LOGERROR, "sanity failed!! trying to send header of type: 0x%02x.",
	  (unsigned char)packet->m_headerType);
      return false;
    }

  int nSize = packetSize[packet->m_headerType];
  int hSize = nSize, cSize = 0;
  char *header, *hptr, *hend, hbuf[RTMP_MAX_HEADER_SIZE], c;

  if (packet->m_body)
    {
      header = packet->m_body - nSize;
      hend = packet->m_body;
    }
  else
    {
      header = hbuf + 6;
      hend = hbuf + sizeof(hbuf);
    }

  if (packet->m_nChannel > 319)
    cSize = 2;
  else if (packet->m_nChannel > 63)
    cSize = 1;
  if (cSize)
    {
      header -= cSize;
      hSize += cSize;
    }

  if (nSize > 1 && packet->m_nInfoField1 >= 0xffffff)
    {
      header -= 4;
      hSize += 4;
    }

  hptr = header;
  c = packet->m_headerType << 6;
  switch (cSize)
    {
    case 0:
      c |= packet->m_nChannel;
      break;
    case 1:
      break;
    case 2:
      c |= 1;
      break;
    }
  *hptr++ = c;
  if (cSize)
    {
      int tmp = packet->m_nChannel - 64;
      *hptr++ = tmp & 0xff;
      if (cSize == 2)
	*hptr++ = tmp >> 8;
    }

  if (nSize > 1)
    {
      uint32_t t = packet->m_nInfoField1;
      if (t > 0xffffff)
	t = 0xffffff;
      hptr = AMF_EncodeInt24(hptr, hend, t);
    }

  if (nSize > 4)
    {
      hptr = AMF_EncodeInt24(hptr, hend, packet->m_nBodySize);
      *hptr++ = packet->m_packetType;
    }

  if (nSize > 8)
    hptr += EncodeInt32LE(hptr, packet->m_nInfoField2);

  if (nSize > 1 && packet->m_nInfoField1 >= 0xffffff)
    hptr = AMF_EncodeInt32(hptr, hend, packet->m_nInfoField1);

  nSize = packet->m_nBodySize;
  char *buffer = packet->m_body;
  int nChunkSize = r->m_outChunkSize;

  Log(LOGDEBUG2, "%s: fd=%d, size=%d", __FUNCTION__, r->m_sb.sb_socket,
      nSize);
  while (nSize + hSize)
    {
      int wrote;

      if (nSize < nChunkSize)
	nChunkSize = nSize;

      if (header)
	{
	  LogHexString(LOGDEBUG2, header, hSize);
	  LogHexString(LOGDEBUG2, buffer, nChunkSize);
	  wrote = WriteN(r, header, nChunkSize + hSize);
	  header = NULL;
	  hSize = 0;
	}
      else
	{
	  LogHexString(LOGDEBUG2, buffer, nChunkSize);
	  wrote = WriteN(r, buffer, nChunkSize);
	}
      if (!wrote)
	return false;

      nSize -= nChunkSize;
      buffer += nChunkSize;

      if (nSize > 0)
	{
	  header = buffer - 1;
	  hSize = 1;
	  if (cSize)
	    {
	      header -= cSize;
	      hSize += cSize;
	    }
	  *header = (0xc0 | c);
	  if (cSize)
	    {
	      int tmp = packet->m_nChannel - 64;
	      header[1] = tmp & 0xff;
	      if (cSize == 2)
		header[2] = tmp >> 8;
	    }
	}
    }

  /* we invoked a remote method */
  if (packet->m_packetType == 0x14)
    {
      AVal method;
      AMF_DecodeString(packet->m_body + 1, &method);
      Log(LOGDEBUG, "Invoking %s", method.av_val);
      /* keep it in call queue till result arrives */
      if (queue)
	AV_queue(&r->m_methodCalls, &r->m_numCalls, &method);
    }

  if (!r->m_vecChannelsOut[packet->m_nChannel])
    r->m_vecChannelsOut[packet->m_nChannel] = malloc(sizeof(RTMPPacket));
  memcpy(r->m_vecChannelsOut[packet->m_nChannel], packet, sizeof(RTMPPacket));
  return true;
}

bool
RTMP_Serve(RTMP *r)
{
  return SHandShake(r);
}

void
RTMP_Close(RTMP *r)
{
  int i;

  if (RTMP_IsConnected(r))
    RTMPSockBuf_Close(&r->m_sb);

  r->m_stream_id = -1;
  r->m_sb.sb_socket = -1;
  r->m_inChunkSize = RTMP_DEFAULT_CHUNKSIZE;
  r->m_outChunkSize = RTMP_DEFAULT_CHUNKSIZE;
  r->m_nBWCheckCounter = 0;
  r->m_nBytesIn = 0;
  r->m_nBytesInSent = 0;
  r->m_nClientBW = 2500000;
  r->m_nClientBW2 = 2;
  r->m_nServerBW = 2500000;

  for (i = 0; i < RTMP_CHANNELS; i++)
    {
      if (r->m_vecChannelsIn[i])
	{
	  RTMPPacket_Free(r->m_vecChannelsIn[i]);
	  free(r->m_vecChannelsIn[i]);
	  r->m_vecChannelsIn[i] = NULL;
	}
      if (r->m_vecChannelsOut[i])
	{
	  free(r->m_vecChannelsOut[i]);
	  r->m_vecChannelsOut[i] = NULL;
	}
    }
  AV_clear(r->m_methodCalls, r->m_numCalls);
  r->m_methodCalls = NULL;
  r->m_numCalls = 0;

  r->m_bPlaying = false;
  r->m_sb.sb_size = 0;

#ifdef CRYPTO
  if (r->Link.dh)
    {
      DH_free(r->Link.dh);
      r->Link.dh = NULL;
    }
  if (r->Link.rc4keyIn)
    {
      free(r->Link.rc4keyIn);
      r->Link.rc4keyIn = NULL;
    }
  if (r->Link.rc4keyOut)
    {
      free(r->Link.rc4keyOut);
      r->Link.rc4keyOut = NULL;
    }
#endif
}

int
RTMPSockBuf_Fill(RTMPSockBuf *sb)
{
  int nBytes;

  if (!sb->sb_size)
    sb->sb_start = sb->sb_buf;

  while (1)
    {
      nBytes = sizeof(sb->sb_buf) - sb->sb_size - (sb->sb_start - sb->sb_buf);
      if (sb->sb_ssl)
	{
	  nBytes = SSL_read(sb->sb_ssl, sb->sb_start + sb->sb_size, nBytes);
	}
      else
	{
	  nBytes = recv(sb->sb_socket, sb->sb_start + sb->sb_size, nBytes, 0);
	}
      if (nBytes != -1)
	{
	  sb->sb_size += nBytes;
	}
      else
	{
	  int sockerr = GetSockError();
	  Log(LOGDEBUG, "%s, recv returned %d. GetSockError(): %d (%s)",
	      __FUNCTION__, nBytes, sockerr, strerror(sockerr));
	  if (sockerr == EINTR && !RTMP_ctrlC)
	    continue;

	  if (sockerr == EWOULDBLOCK || sockerr == EAGAIN)
	    {
	      sb->sb_timedout = true;
	      nBytes = 0;
	    }
	}
      break;
    }

  return nBytes;
}

int
RTMPSockBuf_Send(RTMPSockBuf *sb, const char *buf, int len)
{
  int rc;

#ifdef _DEBUG
  fwrite(buf, 1, len, netstackdump);
#endif

  if (sb->sb_ssl)
    {
      rc = SSL_write(sb->sb_ssl, buf, len);
    }
  else
    {
      rc = send(sb->sb_socket, buf, len, 0);
    }
  return rc;
}

int
RTMPSockBuf_Close(RTMPSockBuf *sb)
{
  int rc;

  if (sb->sb_ssl)
    {
      SSL_shutdown(sb->sb_ssl);
      SSL_free(sb->sb_ssl);
      sb->sb_ssl = NULL;
      rc = 0;
    }
  else
    {
      rc = closesocket(sb->sb_socket);
    }
  return rc;
}

#define HEX2BIN(a)	(((a)&0x40)?((a)&0xf)+9:((a)&0xf))

static void
DecodeTEA(AVal *key, AVal *text)
{
  uint32_t *v, k[4] = { 0 }, u;
  uint32_t z, y, sum = 0, e, DELTA = 0x9e3779b9;
  int32_t p, q;
  int i, n;
  unsigned char *ptr, *out;

  /* prep key: pack 1st 16 chars into 4 LittleEndian ints */
  ptr = (unsigned char *)key->av_val;
  u = 0;
  n = 0;
  v = k;
  p = key->av_len > 16 ? 16 : key->av_len;
  for (i = 0; i < p; i++)
    {
      u |= ptr[i] << (n * 8);
      if (n == 3)
	{
	  *v++ = u;
	  u = 0;
	  n = 0;
	}
      else
	{
	  n++;
	}
    }
  /* any trailing chars */
  if (u)
    *v = u;

  /* prep text: hex2bin, multiples of 4 */
  n = (text->av_len + 7) / 8;
  out = malloc(n * 8);
  ptr = (unsigned char *)text->av_val;
  v = (uint32_t *) out;
  for (i = 0; i < n; i++)
    {
      u = (HEX2BIN(ptr[0]) << 4) + HEX2BIN(ptr[1]);
      u |= ((HEX2BIN(ptr[2]) << 4) + HEX2BIN(ptr[3])) << 8;
      u |= ((HEX2BIN(ptr[4]) << 4) + HEX2BIN(ptr[5])) << 16;
      u |= ((HEX2BIN(ptr[6]) << 4) + HEX2BIN(ptr[7])) << 24;
      *v++ = u;
      ptr += 8;
    }
  v = (uint32_t *) out;

  /* http://www.movable-type.co.uk/scripts/tea-block.html */
#define MX (((z>>5)^(y<<2)) + ((y>>3)^(z<<4))) ^ ((sum^y) + (k[(p&3)^e]^z));
  z = v[n - 1];
  y = v[0];
  q = 6 + 52 / n;
  sum = q * DELTA;
  while (sum != 0)
    {
      e = sum >> 2 & 3;
      for (p = n - 1; p > 0; p--)
	z = v[p - 1], y = v[p] -= MX;
      z = v[n - 1];
      y = v[0] -= MX;
      sum -= DELTA;
    }

  text->av_len /= 2;
  memcpy(text->av_val, out, text->av_len);
  free(out);
}
