#ifndef __RTMP_PACKET__
#define __RTMP_PACKET__
/*
 *      Copyright (C) 2005-2008 Team XBMC
 *      http://www.xbmc.org
 *	Copyright (C) 2008-2009 Andrej Stepanchuk
 *	Copyright (C) 2009 Howard Chu
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

#include <string>
#include <stdint.h>

#define RTMP_PACKET_TYPE_AUDIO 0x08
#define RTMP_PACKET_TYPE_VIDEO 0x09
#define RTMP_PACKET_TYPE_INFO  0x12

#define RTMP_MAX_HEADER_SIZE 14

typedef unsigned char BYTE;

typedef struct
{
	BYTE Type; // 0x03 RTMP, 0x06 RTMPE

} HANDSHAKE_SIGNATURE;

namespace RTMP_LIB
{
  class RTMPPacket
  {
    public:
      RTMPPacket();
      virtual ~RTMPPacket();

      void Reset();
      bool AllocPacket(int nSize);
      void FreePacket();
      void FreePacketHeader();
      
      inline bool IsReady() { return m_nBytesRead == m_nBodySize; }
      void Dump();

      BYTE	m_headerType;
      BYTE	m_packetType;
      int	m_nChannel;
      int32_t	m_nInfoField1; // 3 first bytes
      int32_t	m_nInfoField2; // last 4 bytes in a long header, absolute timestamp for long headers, relative timestamp for short headers 
      bool      m_hasAbsTimestamp; // timestamp absolute or relative?
      uint32_t  m_nTimeStamp; // absolute timestamp
      uint32_t	m_nBodySize;
      uint32_t	m_nBytesRead;
      char 	*m_body;
      char 	*m_buffer;
  };
};

#endif
