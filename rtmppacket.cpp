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

#include <string.h>
#include <stdlib.h>

#include "rtmppacket.h"
#include "log.h"

using namespace RTMP_LIB;

RTMPPacket::RTMPPacket()
{
  Reset();
}

RTMPPacket::~RTMPPacket()
{
  FreePacket();
}

void RTMPPacket::Reset()
{
  m_headerType = 0;
  m_packetType = 0;
  m_nChannel = 0;
  m_nInfoField1 = 0; 
  m_nInfoField2 = 0; 
  m_hasAbsTimestamp = false;
  m_nBodySize = 0;
  m_nBytesRead = 0;
  m_body = NULL;
  m_buffer = NULL;
}

bool RTMPPacket::AllocPacket(int nSize)
{
  m_buffer = (char *)calloc(1, nSize+RTMP_MAX_HEADER_SIZE);
  if (!m_buffer)
    return false;
  m_body = m_buffer+RTMP_MAX_HEADER_SIZE;
  m_nBytesRead = 0;
  return true;
}

void RTMPPacket::FreePacket()
{
  FreePacketHeader();
  Reset();
}

void RTMPPacket::FreePacketHeader()
{
  if (m_buffer)
    free(m_buffer);
  m_buffer = NULL;
  m_body = NULL;
}

void RTMPPacket::Dump()
{
  Log(LOGDEBUG,"RTMP PACKET: packet type: 0x%02x. channel: 0x%02x. info 1: %d info 2: %d. Body size: %lu. body: 0x%02x", m_packetType, m_nChannel,
           m_nInfoField1, m_nInfoField2, m_nBodySize, m_body?(unsigned char)m_body[0]:0);
}
