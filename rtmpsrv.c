/*  Simple RTMP Server
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

/* This is just a stub for an RTMP server. It doesn't do anything
 * beyond obtaining the connection parameters from the client.
 */

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include <signal.h>
#include <getopt.h>

#include <assert.h>

#include "rtmp.h"
#include "parseurl.h"

#include "thread.h"

#ifdef linux
#include <linux/netfilter_ipv4.h>
#endif

#define RD_SUCCESS		0
#define RD_FAILED		1
#define RD_INCOMPLETE		2

#define PACKET_SIZE 1024*1024

#ifdef WIN32
#define InitSockets()	{\
        WORD version;			\
        WSADATA wsaData;		\
					\
        version = MAKEWORD(1,1);	\
        WSAStartup(version, &wsaData);	}

#define	CleanupSockets()	WSACleanup()
#else
#define InitSockets()
#define	CleanupSockets()
#endif

enum
{
  STREAMING_ACCEPTING,
  STREAMING_IN_PROGRESS,
  STREAMING_STOPPING,
  STREAMING_STOPPED
};

typedef struct
{
  int socket;
  int state;
  int streamID;
  char *connect;

} STREAMING_SERVER;

STREAMING_SERVER *rtmpServer = 0;	// server structure pointer

STREAMING_SERVER *startStreaming(const char *address, int port);
void stopStreaming(STREAMING_SERVER * server);

typedef struct
{
  char *hostname;
  int rtmpport;
  int protocol;
  bool bLiveStream;		// is it a live stream? then we can't seek/resume

  long int timeout;		// timeout connection afte 300 seconds
  uint32_t bufferTime;

  char *rtmpurl;
  AVal playpath;
  AVal swfUrl;
  AVal tcUrl;
  AVal pageUrl;
  AVal app;
  AVal auth;
  AVal swfHash;
  AVal flashVer;
  AVal subscribepath;
  uint32_t swfSize;

  uint32_t dStartOffset;
  uint32_t dStopOffset;
  uint32_t nTimeStamp;
} RTMP_REQUEST;

#define STR2AVAL(av,str)	av.av_val = str; av.av_len = strlen(av.av_val)

/* this request is formed from the parameters and used to initialize a new request,
 * thus it is a default settings list. All settings can be overriden by specifying the
 * parameters in the GET request. */
RTMP_REQUEST defaultRTMPRequest;

#ifdef _DEBUG
uint32_t debugTS = 0;

int pnum = 0;

FILE *netstackdump = NULL;
FILE *netstackdump_read = NULL;
#endif

#define SAVC(x) static const AVal av_##x = AVC(#x)

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
SAVC(_result);
SAVC(createStream);
SAVC(getStreamLength);
SAVC(play);
SAVC(fmsVer);
SAVC(mode);
SAVC(level);
SAVC(code);
SAVC(description);
SAVC(secureToken);

static bool
SendConnectResult(RTMP *r, double txn)
{
  RTMPPacket packet;
  char pbuf[384], *pend = pbuf+sizeof(pbuf);
  AMFObject obj;
  AMFObjectProperty p, op;
  AVal av;

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = 0x14;   // INVOKE
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "FMS/3,5,1,525");
  enc = AMF_EncodeNamedString(enc, pend, &av_fmsVer, &av);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_capabilities, 31.0);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_mode, 1.0);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "status");
  enc = AMF_EncodeNamedString(enc, pend, &av_level, &av);
  STR2AVAL(av, "NetConnection.Connect.Success");
  enc = AMF_EncodeNamedString(enc, pend, &av_code, &av);
  STR2AVAL(av, "Connection succeeded.");
  enc = AMF_EncodeNamedString(enc, pend, &av_description, &av);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_objectEncoding, r->m_fEncoding);
#if 0
  STR2AVAL(av, "58656322c972d6cdf2d776167575045f8484ea888e31c086f7b5ffbd0baec55ce442c2fb");
  enc = AMF_EncodeNamedString(enc, pend, &av_secureToken, &av);
#endif
  STR2AVAL(p.p_name, "version");
  STR2AVAL(p.p_vu.p_aval, "3,5,1,525");
  p.p_type = AMF_STRING;
  obj.o_num = 1;
  obj.o_props = &p;
  op.p_type = AMF_OBJECT;
  STR2AVAL(op.p_name, "data");
  op.p_vu.p_object = obj;
  enc = AMFProp_Encode(&op, enc, pend);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, false);
}

static bool
SendResultNumber(RTMP *r, double txn, double ID)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf+sizeof(pbuf);

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = 0x14;   // INVOKE
  packet.m_nInfoField1 = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeNumber(enc, pend, ID);

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, false);
}

static void
dumpAMF(AMFObject *obj)
{
   int i;
   const char opt[] = "NBSO Z";

   for (i=0; i < obj->o_num; i++)
     {
       AMFObjectProperty *p = &obj->o_props[i];
       LogPrintf(" -C ");
       if (p->p_name.av_val)
         LogPrintf("N");
       LogPrintf("%c:", opt[p->p_type]);
       if (p->p_name.av_val)
         LogPrintf("%.*s:", p->p_name.av_len, p->p_name.av_val);
       switch(p->p_type)
         {
         case AMF_BOOLEAN:
           LogPrintf("%d", p->p_vu.p_number != 0);
           break;
         case AMF_STRING:
           LogPrintf("%.*s", p->p_vu.p_aval.av_len, p->p_vu.p_aval.av_val);
           break;
         case AMF_NUMBER:
           LogPrintf("%f", p->p_vu.p_number);
           break;
         case AMF_OBJECT:
           LogPrintf("1");
           dumpAMF(&p->p_vu.p_object);
           LogPrintf(" -C O:0");
           break;
         case AMF_NULL:
           break;
         default:
           LogPrintf("<type %d>", p->p_type);
         }
    }
}

// Returns 0 for OK/Failed/error, 1 for 'Stop or Complete'
int
ServeInvoke(STREAMING_SERVER *server, RTMP * r, RTMPPacket *packet, unsigned int offset)
{
  const char *body;
  unsigned int nBodySize;
  int ret = 0, nRes;

  body = packet->m_body + offset;
  nBodySize = packet->m_nBodySize - offset;

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
  Log(LOGDEBUG, "%s, client invoking <%s>", __FUNCTION__, method.av_val);

  if (AVMATCH(&method, &av_connect))
    {
      AMFObject cobj;
      AVal pname, pval;
      int i;

      server->connect = packet->m_body;
      packet->m_body = NULL;

      AMFProp_GetObject(AMF_GetProp(&obj, NULL, 2), &cobj);
      for (i=0; i<cobj.o_num; i++)
        {
          pname = cobj.o_props[i].p_name;
          pval.av_val = NULL;
          pval.av_len = 0;
          if (cobj.o_props[i].p_type == AMF_STRING)
            pval = cobj.o_props[i].p_vu.p_aval;
          if (AVMATCH(&pname, &av_app))
            {
              r->Link.app = pval;
              pval.av_val = NULL;
            }
          else if (AVMATCH(&pname, &av_flashVer))
            {
              r->Link.flashVer = pval;
              pval.av_val = NULL;
            }
          else if (AVMATCH(&pname, &av_swfUrl))
            {
              r->Link.swfUrl = pval;
              pval.av_val = NULL;
            }
          else if (AVMATCH(&pname, &av_tcUrl))
            {
              r->Link.tcUrl = pval;
              pval.av_val = NULL;
            }
          else if (AVMATCH(&pname, &av_pageUrl))
            {
              r->Link.pageUrl = pval;
              pval.av_val = NULL;
            }
          else if (AVMATCH(&pname, &av_audioCodecs))
            {
              r->m_fAudioCodecs = cobj.o_props[i].p_vu.p_number;
            }
          else if (AVMATCH(&pname, &av_videoCodecs))
            {
              r->m_fVideoCodecs = cobj.o_props[i].p_vu.p_number;
            }
          else if (AVMATCH(&pname, &av_objectEncoding))
            {
              r->m_fEncoding = cobj.o_props[i].p_vu.p_number;
            }
        }
      /* Still have more parameters? Copy them */
      if (obj.o_num > 3)
        {
          int i = obj.o_num - 3;
          r->Link.extras.o_num = i;
          r->Link.extras.o_props = malloc(i*sizeof(AMFObjectProperty));
          memcpy(r->Link.extras.o_props, obj.o_props+3, i*sizeof(AMFObjectProperty));
          obj.o_num = 3;
        }
      SendConnectResult(r, txn);
    }
  else if (AVMATCH(&method, &av_createStream))
    {
      SendResultNumber(r, txn, ++server->streamID);
    }
  else if (AVMATCH(&method, &av_getStreamLength))
    {
      SendResultNumber(r, txn, 10.0);
    }
  else if (AVMATCH(&method, &av_play))
    {
      RTMPPacket pc = {0};
      AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &r->Link.playpath);
      r->Link.seekTime = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 4));
      if (obj.o_num > 5)
        r->Link.length = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 5));
      if (r->Link.tcUrl.av_len)
        {
          LogPrintf("\nrtmpdump -r \"%s\"", r->Link.tcUrl.av_val);
          if (r->Link.app.av_val)
            LogPrintf(" -a \"%s\"", r->Link.app.av_val);
          if (r->Link.flashVer.av_val)
            LogPrintf(" -f \"%s\"", r->Link.flashVer.av_val);
          if (r->Link.swfUrl.av_val)
            LogPrintf(" -W \"%s\"", r->Link.swfUrl.av_val);
          LogPrintf(" -t \"%s\"", r->Link.tcUrl.av_val);
          if (r->Link.pageUrl.av_val)
            LogPrintf(" -p \"%s\"", r->Link.pageUrl.av_val);
          if (r->Link.auth.av_val)
            LogPrintf(" -u \"%s\"", r->Link.auth.av_val);
          if (r->Link.extras.o_num)
            {
              dumpAMF(&r->Link.extras);
              AMF_Reset(&r->Link.extras);
            }
          LogPrintf(" -y \"%.*s\" -o output.flv\n\n",
            r->Link.playpath.av_len, r->Link.playpath.av_val);
        }
      pc.m_body = server->connect;
      server->connect = NULL;
      RTMPPacket_Free(&pc);
      ret = 1;
    }
  AMF_Reset(&obj);
  return ret;
}

int
ServePacket(STREAMING_SERVER *server, RTMP *r, RTMPPacket *packet)
{
  int ret = 0;

  Log(LOGDEBUG, "%s, received packet type %02X, size %lu bytes", __FUNCTION__,
    packet->m_packetType, packet->m_nBodySize);

  switch (packet->m_packetType)
    {
    case 0x01:
      // chunk size
//      HandleChangeChunkSize(r, packet);
      break;

    case 0x03:
      // bytes read report
      break;

    case 0x04:
      // ctrl
//      HandleCtrl(r, packet);
      break;

    case 0x05:
      // server bw
//      HandleServerBW(r, packet);
      break;

    case 0x06:
      // client bw
 //     HandleClientBW(r, packet);
      break;

    case 0x08:
      // audio data
      //Log(LOGDEBUG, "%s, received: audio %lu bytes", __FUNCTION__, packet.m_nBodySize);
      break;

    case 0x09:
      // video data
      //Log(LOGDEBUG, "%s, received: video %lu bytes", __FUNCTION__, packet.m_nBodySize);
      break;

    case 0x0F:			// flex stream send
      break;

    case 0x10:			// flex shared object
      break;

    case 0x11:			// flex message
      {
	Log(LOGDEBUG, "%s, flex message, size %lu bytes, not fully supported",
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

	ServeInvoke(server, r, packet, 1);
	break;
      }
    case 0x12:
      // metadata (notify)
      break;

    case 0x13:
      /* shared object */
      break;

    case 0x14:
      // invoke
      Log(LOGDEBUG, "%s, received: invoke %lu bytes", __FUNCTION__,
	  packet->m_nBodySize);
      //LogHex(packet.m_body, packet.m_nBodySize);

      if (ServeInvoke(server, r, packet, 0))
        RTMP_Close(r);
      break;

    case 0x16:
      /* flv */
	break;
    default:
      Log(LOGDEBUG, "%s, unknown packet type received: 0x%02x", __FUNCTION__,
	  packet->m_packetType);
#ifdef _DEBUG
      LogHex(LOGDEBUG, packet->m_body, packet->m_nBodySize);
#endif
    }
  return ret;
}

TFTYPE
controlServerThread(void *unused)
{
  char ich;
  while (1)
    {
      ich = getchar();
      switch (ich)
	{
	case 'q':
	  LogPrintf("Exiting\n");
	  stopStreaming(rtmpServer);
	  exit(0);
	  break;
	default:
	  LogPrintf("Unknown command \'%c\', ignoring\n", ich);
	}
    }
  TFRET();
}


void doServe(STREAMING_SERVER * server,	// server socket and state (our listening socket)
  int sockfd	// client connection socket
  )
{
  server->state = STREAMING_IN_PROGRESS;

  RTMP rtmp = { 0 };		/* our session with the real client */
  RTMPPacket packet = { 0 };

  // timeout for http requests
  fd_set fds;
  struct timeval tv;

  memset(&tv, 0, sizeof(struct timeval));
  tv.tv_sec = 5;

  FD_ZERO(&fds);
  FD_SET(sockfd, &fds);

  if (select(sockfd + 1, &fds, NULL, NULL, &tv) <= 0)
    {
      Log(LOGERROR, "Request timeout/select failed, ignoring request");
      goto quit;
    }
  else
    {
      RTMP_Init(&rtmp);
      rtmp.m_socket = sockfd;
      if (!RTMP_Serve(&rtmp))
        {
          Log(LOGERROR, "Handshake failed");
          goto cleanup;
        }
    }
  while (RTMP_IsConnected(&rtmp) && RTMP_ReadPacket(&rtmp, &packet))
    {
      if (!RTMPPacket_IsReady(&packet))
        continue;
      ServePacket(server, &rtmp, &packet);
      RTMPPacket_Free(&packet);
    }

cleanup:
  LogPrintf("Closing connection... ");
  RTMP_Close(&rtmp);
  /* Should probably be done by RTMP_Close() ... */
  rtmp.Link.playpath.av_val = NULL;
  rtmp.Link.tcUrl.av_val = NULL;
  rtmp.Link.swfUrl.av_val = NULL;
  rtmp.Link.pageUrl.av_val = NULL;
  rtmp.Link.app.av_val = NULL;
  rtmp.Link.auth.av_val = NULL;
  rtmp.Link.flashVer.av_val = NULL;
  LogPrintf("done!\n\n");

quit:
  if (server->state == STREAMING_IN_PROGRESS)
    server->state = STREAMING_ACCEPTING;

  return;
}

TFTYPE
serverThread(void *arg)
{
  STREAMING_SERVER *server = arg;
  server->state = STREAMING_ACCEPTING;

  while (server->state == STREAMING_ACCEPTING)
    {
      struct sockaddr_in addr;
      socklen_t addrlen = sizeof(struct sockaddr_in);
      int sockfd =
	accept(server->socket, (struct sockaddr *) &addr, &addrlen);

      if (sockfd > 0)
	{
#ifdef linux
          struct sockaddr_in dest;
	  char destch[16];
          socklen_t destlen = sizeof(struct sockaddr_in);
	  getsockopt(sockfd, SOL_IP, SO_ORIGINAL_DST, &dest, &destlen);
          strcpy(destch, inet_ntoa(dest.sin_addr));
	  Log(LOGDEBUG, "%s: accepted connection from %s to %s\n", __FUNCTION__,
	      inet_ntoa(addr.sin_addr), destch);
#else
	  Log(LOGDEBUG, "%s: accepted connection from %s\n", __FUNCTION__,
	      inet_ntoa(addr.sin_addr));
#endif
	  /* Create a new thread and transfer the control to that */
	  doServe(server, sockfd);
	  Log(LOGDEBUG, "%s: processed request\n", __FUNCTION__);
	}
      else
	{
	  Log(LOGERROR, "%s: accept failed", __FUNCTION__);
	}
    }
  server->state = STREAMING_STOPPED;
  TFRET();
}

STREAMING_SERVER *
startStreaming(const char *address, int port)
{
  struct sockaddr_in addr;
  int sockfd, tmp;
  STREAMING_SERVER *server;

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd == -1)
    {
      Log(LOGERROR, "%s, couldn't create socket", __FUNCTION__);
      return 0;
    }

  tmp = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
				(char *) &tmp, sizeof(tmp) );

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(address);	//htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  if (bind(sockfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) ==
      -1)
    {
      Log(LOGERROR, "%s, TCP bind failed for port number: %d", __FUNCTION__,
	  port);
      return 0;
    }

  if (listen(sockfd, 10) == -1)
    {
      Log(LOGERROR, "%s, listen failed", __FUNCTION__);
      closesocket(sockfd);
      return 0;
    }

  server = (STREAMING_SERVER *) calloc(1, sizeof(STREAMING_SERVER));
  server->socket = sockfd;

  ThreadCreate(serverThread, server);

  return server;
}

void
stopStreaming(STREAMING_SERVER * server)
{
  assert(server);

  if (server->state != STREAMING_STOPPED)
    {
      if (server->state == STREAMING_IN_PROGRESS)
	{
	  server->state = STREAMING_STOPPING;

	  // wait for streaming threads to exit
	  while (server->state != STREAMING_STOPPED)
	    msleep(1);
	}

      if (closesocket(server->socket))
	Log(LOGERROR, "%s: Failed to close listening socket, error %d",
	    GetSockError());

      server->state = STREAMING_STOPPED;
    }
}


void
sigIntHandler(int sig)
{
  RTMP_ctrlC = true;
  LogPrintf("Caught signal: %d, cleaning up, just a second...\n", sig);
  if (rtmpServer)
    stopStreaming(rtmpServer);
  signal(SIGINT, SIG_DFL);
}

int
main(int argc, char **argv)
{
  int nStatus = RD_SUCCESS;

  // http streaming server
  char DEFAULT_HTTP_STREAMING_DEVICE[] = "0.0.0.0";	// 0.0.0.0 is any device

  char *rtmpStreamingDevice = DEFAULT_HTTP_STREAMING_DEVICE;	// streaming device, default 0.0.0.0
  int nRtmpStreamingPort = 1935;	// port

  LogPrintf("RTMP Server %s\n", RTMPDUMP_VERSION);
  LogPrintf("(c) 2010 Andrej Stepanchuk, Howard Chu; license: GPL\n\n");

  debuglevel = LOGINFO;

  if (argc > 1 && !strcmp(argv[1], "-z"))
    debuglevel = LOGALL;

  // init request
  memset(&defaultRTMPRequest, 0, sizeof(RTMP_REQUEST));

  defaultRTMPRequest.rtmpport = -1;
  defaultRTMPRequest.protocol = RTMP_PROTOCOL_UNDEFINED;
  defaultRTMPRequest.bLiveStream = false;	// is it a live stream? then we can't seek/resume

  defaultRTMPRequest.timeout = 300;	// timeout connection afte 300 seconds
  defaultRTMPRequest.bufferTime = 20 * 1000;


  signal(SIGINT, sigIntHandler);
#ifndef WIN32
  signal(SIGPIPE, SIG_IGN);
#endif

#ifdef _DEBUG
  netstackdump = fopen("netstackdump", "wb");
  netstackdump_read = fopen("netstackdump_read", "wb");
#endif

  InitSockets();

  // start text UI
  ThreadCreate(controlServerThread, 0);

  // start http streaming
  if ((rtmpServer =
       startStreaming(rtmpStreamingDevice, nRtmpStreamingPort)) == 0)
    {
      Log(LOGERROR, "Failed to start RTMP server, exiting!");
      return RD_FAILED;
    }
  LogPrintf("Streaming on rtmp://%s:%d\n", rtmpStreamingDevice,
	    nRtmpStreamingPort);

  while (rtmpServer->state != STREAMING_STOPPED)
    {
      sleep(1);
    }
  Log(LOGDEBUG, "Done, exiting...");

  CleanupSockets();

#ifdef _DEBUG
  if (netstackdump != 0)
    fclose(netstackdump);
  if (netstackdump_read != 0)
    fclose(netstackdump_read);
#endif
  return nStatus;
}
