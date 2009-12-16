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

//#include <string>
//#include <vector>

#ifdef WIN32
#include <winsock.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#endif

#include "log.h"

#ifdef CRYPTO
#include "dh.h"
#endif

#include "AMFObject.h"
#include "rtmppacket.h"

#define RTMP_PROTOCOL_UNDEFINED	-1
#define RTMP_PROTOCOL_RTMP      0
#define RTMP_PROTOCOL_RTMPT     1 // not yet supported
#define RTMP_PROTOCOL_RTMPS     2 // not yet supported
#define RTMP_PROTOCOL_RTMPE     3
#define RTMP_PROTOCOL_RTMPTE    4 // not yet supported
#define RTMP_PROTOCOL_RTMFP     5 // not yet supported

#define RTMP_DEFAULT_CHUNKSIZE	128

extern char RTMPProtocolStringsLower[][7];

int32_t GetTime();

inline int GetSockError() {
#ifdef WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
}

namespace RTMP_LIB
{

typedef struct
{
        const char *hostname;
        unsigned int port;
	int protocol;
	const char *playpath;

        const char *tcUrl;
        const char *swfUrl;
        const char *pageUrl;
        const char *app;
        const char *auth;
	const char *SWFHash;
	uint32_t SWFSize;
	const char *flashVer;
	const char *subscribepath;

	double seekTime;
	uint32_t length;
	bool bLiveStream;

	long int timeout; // number of seconds before connection times out
	
	#ifdef CRYPTO
	DH *dh; // for encryption
	RC4_KEY *rc4keyIn;
	RC4_KEY *rc4keyOut;

	//char SWFHashHMAC[32];
	char SWFVerificationResponse[42];
	#endif

        const char *sockshost;
        unsigned short socksport;
} LNK;

class CRTMP
  {
    public:

      CRTMP();
      virtual ~CRTMP();

      void SetBufferMS(int size);
      void UpdateBufferMS();

      void SetupStream(
      	int protocol, 
	const char *hostname, 
	unsigned int port, 
        const char *sockshost,
	const char *playpath, 
	const char *tcUrl, 
	const char *swfUrl, 
	const char *pageUrl, 
	const char *app, 
	const char *auth,
	const char *swfSHA256Hash,
	uint32_t swfSize,
	const char *flashVer, 
	const char *subscribepath, 
      	double dTime,
      	uint32_t dLength,
	bool bLiveStream,
	long int timeout=300);

      bool Connect();

      bool IsConnected(); 
      bool IsTimedout(); 
      double GetDuration();
      bool ToggleStream();

      bool ConnectStream(double seekTime=-10.0, uint32_t dLength=0);
      bool ReconnectStream(int bufferTime, double seekTime=-10.0, uint32_t dLength=0);
      void DeleteStream();
      int GetNextMediaPacket(RTMPPacket &packet);

      void Close();

      static int EncodeString(char *output, const std::string &strValue);
      static int EncodeNumber(char *output, double dVal);
      static int EncodeInt16(char *output, short nVal);
      static int EncodeInt24(char *output, int nVal);
      static int EncodeInt32(char *output, int nVal);
      static int EncodeBoolean(char *output,bool bVal);

      static unsigned short ReadInt16(const char *data);
      static unsigned int  ReadInt24(const char *data);
      static unsigned int  ReadInt32(const char *data);
      static std::string ReadString(const char *data);
      static bool ReadBool(const char *data);
      static double ReadNumber(const char *data);
	  bool SendPause(bool DoPause, double dTime);

	  static bool DumpMetaData(AMFObject &obj);
      static bool FindFirstMatchingProperty(AMFObject &obj, std::string name, AMFObjectProperty &p);

    protected:
      bool HandShake(bool FP9HandShake=true);
      bool RTMPConnect();
      bool SocksNegotiate();

      bool SendConnectPacket();
      bool SendServerBW();
      bool SendCheckBW();
      bool SendCheckBWResult(double txn);
      bool SendCtrl(short nType, unsigned int nObject, unsigned int nTime = 0);
      bool SendBGHasStream(double dId, char *playpath);
      bool SendCreateStream(double dStreamId);
      bool SendDeleteStream(double dStreamId);
      bool SendFCSubscribe(const char *subscribepath);
      bool SendPlay();
      bool SendSeek(double dTime);
      bool SendBytesReceived();

      int HandlePacket(RTMPPacket &packet);
      int HandleInvoke(const char *body, unsigned int nBodySize);
      bool HandleMetadata(char *body, unsigned int len);
      void HandleChangeChunkSize(const RTMPPacket &packet);
      void HandleAudio(const RTMPPacket &packet);
      void HandleVideo(const RTMPPacket &packet);
      void HandleCtrl(const RTMPPacket &packet);
      void HandleServerBW(const RTMPPacket &packet);
      void HandleClientBW(const RTMPPacket &packet);
     
      int EncodeString(char *output, const std::string &strName, const std::string &strValue);
      int EncodeNumber(char *output, const std::string &strName, double dVal);
      int EncodeBoolean(char *output, const std::string &strName, bool bVal);

      bool SendRTMP(RTMPPacket &packet);

      bool ReadPacket(RTMPPacket &packet);
      int  ReadN(char *buffer, int n);
      bool WriteN(const char *buffer, int n);

      bool FillBuffer();
	  void FlushBuffer();

      int  m_socket;
      int  m_chunkSize;
      int  m_nBWCheckCounter;
      int  m_nBytesIn;
      int  m_nBytesInSent;
      int  m_nBufferMS;
      int  m_stream_id; // returned in _result from invoking createStream
      int  m_mediaChannel;
      uint32_t  m_mediaStamp;
      uint32_t  m_pauseStamp;
      int m_bPausing;
      int m_nServerBW;
      int m_nClientBW;
      uint8_t m_nClientBW2;
      bool m_bPlaying;
      bool m_bTimedout;

      //std::string m_strPlayer;
      //std::string m_strPageUrl;
      //std::string m_strLink;
      //std::string m_strPlayPath;

      std::vector<std::string> m_methodCalls; //remote method calls queue

      LNK Link;
      char *m_pBuffer;      // data read from socket
      char *m_pBufferStart; // pointer into m_pBuffer of next byte to process
      int  m_nBufferSize;   // number of unprocessed bytes in buffer
      RTMPPacket *m_vecChannelsIn[65600];
      RTMPPacket *m_vecChannelsOut[65600];
      int  m_channelTimestamp[65600]; // abs timestamp of last packet

      double m_fAudioCodecs; // audioCodecs for the connect packet
      double m_fVideoCodecs; // videoCodecs for the connect packet

      double m_fDuration; // duration of stream in seconds
  };
};

#endif
