/*
 *      Copyright (C) 2005-2008 Team XBMC
 *      http://www.xbmc.org
 *      Copyright (C) 2008-2009 Andrej Stepanchuk
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
#include <assert.h>
//#include <stdlib.h>
//#include <stdio.h>
//#include <time.h>
//#include <arpa/inet.h>

#ifdef WIN32
#include <winsock.h> // for htons
#endif

#include "AMFObject.h"
#include "log.h"
#include "rtmp.h"
#include "bytes.h"

RTMP_LIB::AMFObjectProperty RTMP_LIB::AMFObject::m_invalidProp;

RTMP_LIB::AMFObjectProperty::AMFObjectProperty()
{
  Reset();
}

RTMP_LIB::AMFObjectProperty::AMFObjectProperty(const std::string & strName, double dValue)
{
  Reset();
}

RTMP_LIB::AMFObjectProperty::AMFObjectProperty(const std::string & strName, bool bValue)
{
  Reset();
}

RTMP_LIB::AMFObjectProperty::AMFObjectProperty(const std::string & strName, const std::string & strValue)
{
  Reset();
}

RTMP_LIB::AMFObjectProperty::AMFObjectProperty(const std::string & strName, const AMFObject & objValue)
{
  Reset();
}

RTMP_LIB::AMFObjectProperty::~ AMFObjectProperty()
{
}

const std::string &RTMP_LIB::AMFObjectProperty::GetPropName() const
{
  return m_strName;
}

void RTMP_LIB::AMFObjectProperty::SetPropName(const std::string& strName)
{
  m_strName = strName;
}

RTMP_LIB::AMFDataType RTMP_LIB::AMFObjectProperty::GetType() const
{
  return m_type;
}

double RTMP_LIB::AMFObjectProperty::GetNumber() const
{
  return m_dNumVal;
}

bool RTMP_LIB::AMFObjectProperty::GetBoolean() const
{
  return m_dNumVal != 0;
}

const std::string &RTMP_LIB::AMFObjectProperty::GetString() const
{
  return m_strVal;
}

const RTMP_LIB::AMFObject &RTMP_LIB::AMFObjectProperty::GetObject() const
{
  return m_objVal;
}

bool RTMP_LIB::AMFObjectProperty::IsValid() const
{
  return (m_type != AMF_INVALID);
}

int RTMP_LIB::AMFObjectProperty::Encode(char * pBuffer, int nSize) const
{
  int nBytes = 0;
  
  if (m_type == AMF_INVALID)
    return -1;

  if (m_type != AMF_NULL && nSize < (int)m_strName.size() + (int)sizeof(short) + 1)
    return -1;

  if (m_type != AMF_NULL && !m_strName.empty())
  {
    nBytes += EncodeName(pBuffer);
    pBuffer += nBytes;
    nSize -= nBytes;
  }

  switch (m_type)
  {
    case AMF_NUMBER:
      if (nSize < 9)
        return -1;
      nBytes += RTMP_LIB::CRTMP::EncodeNumber(pBuffer, GetNumber());
      break;

    case AMF_BOOLEAN:
      if (nSize < 2)
        return -1;
      nBytes += RTMP_LIB::CRTMP::EncodeBoolean(pBuffer, GetBoolean());
      break;

    case AMF_STRING:
      if (nSize < (int)m_strVal.size() + (int)sizeof(short))
        return -1;
      nBytes += RTMP_LIB::CRTMP::EncodeString(pBuffer, GetString());
      break;

    case AMF_NULL:
      if (nSize < 1)
        return -1;
      *pBuffer = 0x05;
      nBytes += 1;
      break;

    case AMF_OBJECT:
    {
      int nRes = m_objVal.Encode(pBuffer, nSize);
      if (nRes == -1)
        return -1;

      nBytes += nRes;
      break;
    }
    default:
      Log(LOGERROR,"%s, invalid type. %d", __FUNCTION__, m_type);
      return -1;
  };  

  return nBytes;
}

//* TODO AMF3
#define AMF3_INTEGER_MAX	268435455
#define AMF3_INTEGER_MIN	-268435456

int AMF3ReadInteger(const char *data, int32_t *val)
{
	//LogHex(data, 4);
	int i=0;

	while(i<=2) { // handle first 3 bytes
		if(data[i] & 0x80) { // byte used
			(*val) <<= 7;   // shift up
			(*val) |= (data[i] & 0x7f); // add bits
			i++;
		} else { break; }
	}

	if(i>2) { // use 4th byte, all 8bits
		(*val) <<= 8;
		(*val) |= data[3];

		// range check
		if((*val) > AMF3_INTEGER_MAX)
			(*val) -= (1<<29);
	} else { // use 7bits of last unparsed byte (0xxxxxxx)
		(*val) <<= 7;
		(*val) |= data[i];
	}

	//Log(LOGDEBUG, "%s, AMF3 integer: %d, size: %d", __FUNCTION__, *val, i>2 ? 4 : i+1);

	return i>2 ? 4 : i+1;
}

int AMF3ReadString(const char *data, char **pStr)
{
	assert(pStr != 0);

	int32_t ref = 0;
	int len = AMF3ReadInteger(data, &ref);
	data += len;

	if((ref & 0x1) == 0) { // reference: 0xxx
		uint32_t refIndex = (ref >> 1);
		Log(LOGDEBUG, "%s, string reference, index: %d, not supported, ignoring!", refIndex);
		return len;
	} else {
		uint32_t nSize = (ref >> 1);

		//Log(LOGDEBUG, "AMF3 String, len: %d, data: |%s|", nSize, data);

		(*pStr) = new char[nSize+1];
		memcpy(*pStr, data, nSize);
		(*pStr)[nSize]=0;

		return len+nSize;
	}
	return len;
}

int RTMP_LIB::AMFObjectProperty::AMF3Decode(const char * pBuffer, int nSize, bool bDecodeName)
{
	int nOriginalSize = nSize;

	if (nSize == 0 || !pBuffer) {
    		Log(LOGDEBUG,"empty buffer/no buffer pointer!");
    		return -1;
  	}

	//Log(LOGDEBUG, "Decoding property:");
	//LogHex(pBuffer, nSize);

	// decode name
	if(bDecodeName) {
		char *name;
		int nRes = AMF3ReadString(pBuffer, &name);

		if(strlen(name) <= 0)
			return nRes;

		//Log(LOGDEBUG, "AMF3 Property name: |%s|, size: %d", name, strlen(name));
		m_strName = name;
		pBuffer += nRes;
		nSize -= nRes;
	}

	// decode
	uint8_t type = *pBuffer;

	nSize--;
	pBuffer++;

	switch(type)
	{
		case 0x00: // AMF3_UNDEFINED
		case 0x01: // AMF3_NULL
			//Log(LOGDEBUG, "AMF3_UNDEFINED/NULL");
			m_type = AMF_NULL;
			break;
		case 0x02: // AMF3_FALSE
			//Log(LOGDEBUG, "AMF3_FALSE");
			m_type = AMF_BOOLEAN;
			m_dNumVal = 0.0;
			break;
		case 0x03: // AMF3_TRUE
			//Log(LOGDEBUG, "AMF3_TRUE");
			m_type = AMF_BOOLEAN;
                        m_dNumVal = 1.0;
                        break;
		case 0x04: // AMF3_INTEGER
		{
			int32_t res = 0;
			int len = AMF3ReadInteger(pBuffer, &res);
			//Log(LOGDEBUG, "AMF3_INTEGER: %d", res);
			
			m_type = AMF_NUMBER;

			nSize -= len;
			m_dNumVal = (double)res;
			break;
		}
		case 0x0A: // AMF3_OBJECT
		{
			Log(LOGDEBUG, "AMF3_OBJECT");

			int nRes = m_objVal.AMF3Decode(pBuffer, nSize, true);
      			if(nRes == -1)
        			return -1;
      			nSize -= nRes;
      			m_type = AMF_OBJECT;
			break;
		}
		case 0x06: // AMF3_STRING
		{
			//Log(LOGDEBUG, "AMF3_STRING");
			//LogHex(pBuffer, nSize);
			
			char *str = 0;
			int len = AMF3ReadString(pBuffer, &str);
			//Log(LOGDEBUG, "AMF3_STRING: %s", str);
			m_strVal = str;
			delete [] str;
			m_type = AMF_STRING;
			nSize -= len;
			break;
		}
		case 0x0B: // AMF3_XML_STRING, not tested
		case 0x07: // AMF3_XML_DOC
		{
			Log(LOGDEBUG, "AMF3_XML_DOC");
			
			char *str = 0;
                        int len = AMF3ReadString(pBuffer, &str);
			m_strVal = str;
                        delete [] str;
                        m_type = AMF_STRING;
                        nSize -= len;
                        break;
		}
		case 0x05: // AMF3_NUMBER
			Log(LOGDEBUG, "AMF3_NUMBER");
			if (nSize < 8)
        			return -1;
			m_dNumVal = ReadNumber(pBuffer);
			nSize -= 8;
			m_type = AMF_NUMBER;
			break;
		case 0x08: // AMF3_DATE, not tested
		{
			int32_t res = 0;
                        int len = AMF3ReadInteger(pBuffer, &res);

			nSize -= len;
			pBuffer += len;

			if((res & 0x1) == 0) { // reference
				uint32_t nIndex = (res >> 1);
				Log(LOGDEBUG, "AMF3_DATE reference: %d, not supported!", nIndex);
			} else {
				if(nSize < 8)
                                	return -1;
                        	
				m_dNumVal = ReadNumber(pBuffer);
                        	nSize -= 8;
                        	m_type = AMF_NUMBER;	
			}	
			break;
		}
		case 0x09: // AMF3_ARRAY
		case 0x0C: // AMF3_BYTE_ARRAY
		default:
			Log(LOGDEBUG,"%s - AMF3 unknown/unsupported datatype 0x%02x, @0x%08X", __FUNCTION__, (unsigned char)(*pBuffer), pBuffer);
			return -1;
	}

	return nOriginalSize - nSize;
}
//*/

int RTMP_LIB::AMFObjectProperty::Decode(const char * pBuffer, int nSize, bool bDecodeName) 
{
  int nOriginalSize = nSize;

  if (nSize == 0 || !pBuffer) {
    Log(LOGDEBUG,"%s: Empty buffer/no buffer pointer!", __FUNCTION__);
    return -1;
  }
  
  if (bDecodeName && nSize < 4) { // at least name (length + at least 1 byte) and 1 byte of data
    Log(LOGDEBUG,"%s: Not enough data for decoding with name, less then 4 bytes!", __FUNCTION__);
    return -1;
  }

  if (bDecodeName)
  {
    unsigned short nNameSize = RTMP_LIB::CRTMP::ReadInt16(pBuffer);
    if (nNameSize > nSize - 2) {
      Log(LOGDEBUG,"%s: Name size out of range: namesize (%d) > len (%d) - 2", __FUNCTION__, nNameSize, nSize);
      return -1;
    }

    m_strName = RTMP_LIB::CRTMP::ReadString(pBuffer);
    nSize -= 2 + m_strName.size();
    pBuffer += 2 + m_strName.size();

    //Log(LOGDEBUG, "%s: Decoded name: %s", __FUNCTION__, m_strName.c_str());
  }

  if (nSize == 0) {
    return -1;
  }

  nSize--;

  switch (*pBuffer)
  {
    case 0x00: // AMF_NUMBER:
      if (nSize < 8)
        return -1;
      m_dNumVal = ReadNumber(pBuffer+1);
      nSize -= 8;
      m_type = AMF_NUMBER;
      break;
    case 0x01: // AMF_BOOLEAN:
      if (nSize < 1)
        return -1;
      m_dNumVal = (double)RTMP_LIB::CRTMP::ReadBool(pBuffer+1);
      nSize--;
      m_type = AMF_BOOLEAN;
      break;
    case 0x02: // AMF_STRING:
    {
      unsigned short nStringSize = RTMP_LIB::CRTMP::ReadInt16(pBuffer+1);
      //Log(LOGDEBUG, "Read string, len: %d\n", nStringSize);
      //LogHex(pBuffer, nSize);

      if (nSize < (long)nStringSize + 2)
        return -1;
      m_strVal = RTMP_LIB::CRTMP::ReadString(pBuffer+1);
      nSize -= (2 + nStringSize);
      m_type = AMF_STRING;
      break;
    }
    case 0x03: // AMF_OBJECT:
    {
      int nRes = m_objVal.Decode(pBuffer+1, nSize, true);
      if (nRes == -1)
        return -1;
      nSize -= nRes;
      m_type = AMF_OBJECT;
      break;
    }
    case 0x04: // AMF_MOVIE_CLIP
    {
      Log(LOGERROR, "AMF_MOVIE_CLIP not supported!");
      return -1;
      break;
    }
    case 0x07: // AMF_REFERENCE
    {
      Log(LOGERROR, "AMF_REFERENCE not supported!");
      return -1;
      break;
    }
    case 0x0A: // AMF_ARRAY
    {
      unsigned int nArrayLen = RTMP_LIB::CRTMP::ReadInt32(pBuffer+1);
      nSize -= 4;
      
      int nRes = m_objVal.DecodeArray(pBuffer+5, nSize, nArrayLen, false);
      if (nRes == -1)
        return -1;
      nSize -= nRes;
      m_type = AMF_OBJECT; 
      break;
    }
    case 0x08: // AMF_MIXEDARRAY
    {
      //int nMaxIndex = RTMP_LIB::CRTMP::ReadInt32(pBuffer+1); // can be zero for unlimited
      nSize -= 4;

      // next comes the rest, mixed array has a final 0x000009 mark and names, so its an object
      int nRes = m_objVal.Decode(pBuffer+5, nSize, true);
      if (nRes == -1)
      	return -1;
      nSize -= nRes;
      m_type = AMF_OBJECT; 
      break;
    }
    case 0x05: /* AMF_NULL */
    case 0x06: /* AMF_UNDEFINED */
    case 0x0D: /* AMF_UNSUPPORTED */
        m_type = AMF_NULL;
    	break;
    case 0x0B: // AMF_DATE
    {
      Log(LOGDEBUG, "AMF_DATE");

      if (nSize < 10)
              return -1;

      m_dNumVal = ReadNumber(pBuffer+1);
      m_nUTCOffset = RTMP_LIB::CRTMP::ReadInt16(pBuffer+9);

      m_type = AMF_DATE;
      nSize -= 10;
      break;
    }
    case 0x0C: // AMF_LONG_STRING
    {
    	Log(LOGWARNING, "AMF_LONG_STRING not tested!");
	
    	unsigned int nStringSize = RTMP_LIB::CRTMP::ReadInt32(pBuffer+1);;
        if (nSize < (long)nStringSize + 4)
          return -1;
        m_strVal = RTMP_LIB::CRTMP::ReadString(pBuffer+1);
        nSize -= (4 + nStringSize);
        m_type = AMF_STRING;
	break;
    }
    case 0x0E: // AMF_RECORDSET
    {
    	Log(LOGERROR, "AMF_RECORDSET not supported!");
	return -1;
	break;
    }
    case 0x0F: // AMF_XML
    {
    	Log(LOGERROR, "AMF_XML not supported!");
	return -1;
	break;
    }
    case 0x10: //AMF_CLASS_OBJECT
    {
    	Log(LOGERROR, "AMF_CLASS_OBJECT not supported!");
	return -1;
	break;
    }
    case 0x11: //AMF_AMF3_OBJECT
    {
    	Log(LOGERROR, "AMF_AMF3_OBJECT to be tested!");
	int nRes = m_objVal.AMF3Decode(pBuffer+1, nSize, true);
        if (nRes == -1)
          return -1;
        nSize -= nRes;
        m_type = AMF_OBJECT;
        break;	
    }
    default:
      Log(LOGDEBUG,"%s - unknown datatype 0x%02x, @0x%08X", __FUNCTION__, (unsigned char)(*pBuffer), pBuffer);
      return -1;
  }

  return nOriginalSize - nSize;
}

void RTMP_LIB::AMFObjectProperty::Dump() const
{
  if (m_type == AMF_INVALID)
  {
    Log(LOGDEBUG,"Property: INVALID");
    return;
  }

  if (m_type == AMF_NULL)
  {
    Log(LOGDEBUG,"Property: NULL");
    return;
  }

  if (m_type == AMF_OBJECT)
  {
    Log(LOGDEBUG,"Property: <Name: %25s, OBJECT>", m_strName.empty() ? "no-name." : m_strName.c_str());
    m_objVal.Dump();
    return;
  }

  char strRes[256]="";
  snprintf(strRes, 255, "Name: %25s, ", m_strName.empty()? "no-name.":m_strName.c_str());

  char str[256]="";
  switch(m_type)
  {
    case AMF_NUMBER:
      snprintf(str, 255, "NUMBER:\t%.2f", m_dNumVal);
      break;
    case AMF_BOOLEAN:
      snprintf(str, 255, "BOOLEAN:\t%s", m_dNumVal == 1.?"TRUE":"FALSE");
      break;
    case AMF_STRING:
      snprintf(str, 255, "STRING:\t%s", m_strVal.c_str());
      break;
    case AMF_DATE:
      snprintf(str, 255, "DATE:\ttimestamp: %.2f, UTC offset: %d", m_dNumVal, m_nUTCOffset);
      break;
    default:
      snprintf(str, 255, "INVALID TYPE 0x%02x", (unsigned char)m_type);
  }

  Log(LOGDEBUG,"Property: <%s%s>", strRes, str);
}

void RTMP_LIB::AMFObjectProperty::Reset()
{
  m_dNumVal = 0.;
  m_strVal.clear();
  m_objVal.Reset();
  m_type = AMF_INVALID;
}

int RTMP_LIB::AMFObjectProperty::EncodeName(char *pBuffer) const
{
  short length = htons(m_strName.size());
  memcpy(pBuffer, &length, sizeof(short));
  pBuffer += sizeof(short);

  memcpy(pBuffer, m_strName.c_str(), m_strName.size());
  return m_strName.size() + sizeof(short);
}


// AMFObject

RTMP_LIB::AMFObject::AMFObject()
{
  Reset();
}

RTMP_LIB::AMFObject::~ AMFObject()
{
  Reset();
}

int RTMP_LIB::AMFObject::Encode(char * pBuffer, int nSize) const
{
  if (nSize < 4)
    return -1;

  *pBuffer = 0x03; // object

  int nOriginalSize = nSize;
  for (size_t i=0; i<m_properties.size(); i++)
  {
    int nRes = m_properties[i].Encode(pBuffer, nSize);
    if (nRes == -1)
    {
      Log(LOGERROR,"AMFObject::Encode - failed to encode property in index %d", i);
    }
    else
    {
      nSize -= nRes;
      pBuffer += nRes;
    }
  }

  if (nSize < 3)
    return -1; // no room for the end marker

  RTMP_LIB::CRTMP::EncodeInt24(pBuffer, 0x000009);
  nSize -= 3;

  return nOriginalSize - nSize;
}

int RTMP_LIB::AMFObject::DecodeArray(const char * pBuffer, int nSize, int nArrayLen, bool bDecodeName)
{
  int nOriginalSize = nSize;
  bool bError = false;

  while(nArrayLen > 0)
  {
    nArrayLen--;

    RTMP_LIB::AMFObjectProperty prop;
    int nRes = prop.Decode(pBuffer, nSize, bDecodeName);
    if (nRes == -1)
      bError = true;
    else
    {
      nSize -= nRes;
      pBuffer += nRes;
      m_properties.push_back(prop);
    }
  }
  if (bError)
    return -1;

  return nOriginalSize - nSize;
}

int RTMP_LIB::AMFObject::AMF3Decode(const char * pBuffer, int nSize, bool bAMFData)
{
	int nOriginalSize = nSize;

	if(bAMFData) {
		if(*pBuffer != 0x0A) 
			Log(LOGERROR, "AMF3 Object encapsulated in AMF stream does not start with 0x0A!");
		pBuffer++;
		nSize--;
	}

	int32_t ref = 0;
        int len = AMF3ReadInteger(pBuffer, &ref);
        pBuffer += len;
        nSize -= len;

	if((ref & 1) == 0) { // object reference, 0xxx
		uint32_t objectIndex = (ref >> 1);

		Log(LOGDEBUG, "Object reference, index: %d", objectIndex);
        }
        else // object instance
        {
		int32_t classRef    = (ref >> 1);
		
		AMF3ClassDefinition *classDef = 0;

		if((classRef & 0x1) == 0) { // class reference
			uint32_t classIndex = (classRef >> 1);
			Log(LOGDEBUG, "Class reference: %d", classIndex);
		} else {
        		int32_t classExtRef = (classRef >> 1);

                	bool bExternalizable = ( classExtRef       & 0x1) == 1;
                	bool bDynamic        = ((classExtRef >> 1) & 0x1) == 1;

                	uint32_t numMembers = classExtRef >> 2;

                	// class name
                	char *className = 0;

                	len = AMF3ReadString(pBuffer, &className);
                	nSize -= len;
                	pBuffer += len;

			//std::string str = className;

                	Log(LOGDEBUG, "Class name: %s, externalizable: %d, dynamic: %d, classMembers: %d", className, bExternalizable, bDynamic, numMembers);
			classDef = new AMF3ClassDefinition(className, bExternalizable, bDynamic);
			delete [] className;

                	for(unsigned int i=0; i<numMembers; i++) {
                		char *memberName = 0;
                        	len = AMF3ReadString(pBuffer, &memberName);
                        	Log(LOGDEBUG, "Member: %s", memberName);
                        	classDef->AddProperty(memberName);
                        	delete [] memberName;
                        	nSize -= len;
                        	pBuffer += len;
			}
                }

	        // add as referencable object
        	// ...
        
		if(classDef->isExternalizable()) {
			Log(LOGDEBUG, "Externalizable, TODO check");

			RTMP_LIB::AMFObjectProperty prop;
                        int nRes = prop.AMF3Decode(pBuffer, nSize, false);
                        if(nRes == -1)
                        	Log(LOGDEBUG, "%s, failed to decode AMF3 property!", __FUNCTION__);
			else {
				nSize -= nRes;
				pBuffer += nRes;
			}

			prop.SetPropName("DEFAULT_ATTRIBUTE");
			m_properties.push_back(prop);
        	} else {
			for(int i=0; i<classDef->GetMemberCount(); i++) // non-dynamic
			{
				RTMP_LIB::AMFObjectProperty prop;
				int nRes = prop.AMF3Decode(pBuffer, nSize, false);
				if(nRes == -1)
					Log(LOGDEBUG, "%s, failed to decode AMF3 property!", __FUNCTION__);

				prop.SetPropName(classDef->GetProperty(i));
				//prop.Dump();
				m_properties.push_back(prop);

				pBuffer += nRes;
				nSize -= nRes;
			}
			if(classDef->isDynamic()) {
				int len = 0;

				do {
					RTMP_LIB::AMFObjectProperty prop;
					int nRes = prop.AMF3Decode(pBuffer, nSize, true);
					
					m_properties.push_back(prop);

					pBuffer += nRes;
					nSize -= nRes;

					len = prop.GetPropName().length();
				} while(len > 0);

				// property name
				/*
				RTMP_LIB::AMFObjectProperty prop;
    				int nRes = prop.AMF3Decode(pBuffer, nSize);
				if (nRes == -1)
					Log(LOGDEBUG, "%s, failed to decode AMF3 property!", __FUNCTION__);
      				m_properties.push_back(prop);*/
			}			
		}
		Log(LOGDEBUG, "class object!");
	}

  /*while (nSize > 0) {
  	RTMP_LIB::AMFObjectProperty prop;
	int nRes = prop.AMF3Decode(pBuffer, nSize, bDecodeName);
	if(nRes == -1)
		return -1;
	
	nSize -= nRes;
	pBuffer += nRes;
	//if(prop.GetType() != AMF_NULL)
		m_properties.push_back(prop);
  }*/
  return nOriginalSize - nSize;
}

int RTMP_LIB::AMFObject::Decode(const char * pBuffer, int nSize, bool bDecodeName)
{
  int nOriginalSize = nSize;
  bool bError = false; // if there is an error while decoding - try to at least find the end mark 0x000009

  //Log(LOGDEBUG, "%s: size: %lu, %d", __FUNCTION__, nSize, bDecodeName);

  while (nSize >= 3)
  {
    if (RTMP_LIB::CRTMP::ReadInt24(pBuffer) == 0x000009)
    {
      nSize -= 3;
      bError = false;
      break;
    }

    if (bError)
    {
      Log(LOGERROR,"DECODING ERROR, IGNORING BYTES UNTIL NEXT KNOWN PATTERN!");
      nSize--;
      pBuffer++;
      continue;
    }

    RTMP_LIB::AMFObjectProperty prop;
    int nRes = prop.Decode(pBuffer, nSize, bDecodeName);
    if (nRes == -1)
      bError = true;
    else
    {
      nSize -= nRes;
      pBuffer += nRes;
      m_properties.push_back(prop);
    }
  }

  if (bError)
    return -1;

  return nOriginalSize - nSize;
}

void RTMP_LIB::AMFObject::AddProperty(const AMFObjectProperty & prop)
{
  m_properties.push_back(prop);
}

int RTMP_LIB::AMFObject::GetPropertyCount() const
{
  return m_properties.size();
}

const RTMP_LIB::AMFObjectProperty & RTMP_LIB::AMFObject::GetProperty(const std::string & strName) const
{
  for (size_t n=0; n<m_properties.size(); n++)
  {
    if (m_properties[n].GetPropName() == strName)
      return m_properties[n];
  }

  return m_invalidProp;
}

const RTMP_LIB::AMFObjectProperty & RTMP_LIB::AMFObject::GetProperty(size_t nIndex) const
{
  if (nIndex >= m_properties.size())
    return m_invalidProp;

  return m_properties[nIndex];
}

void RTMP_LIB::AMFObject::Dump() const
{
  //Log(LOGDEBUG,"START AMF Object Dump:");
  
  for (size_t n=0; n<m_properties.size(); n++) {
    m_properties[n].Dump();
  }

  //Log(LOGDEBUG,"END AMF Object Dump");
}

void RTMP_LIB::AMFObject::Reset()
{
  m_properties.clear();
}

// AMF3ClassDefinition
std::string strEmpty = "";

RTMP_LIB::AMF3ClassDefinition::AMF3ClassDefinition(const std::string &strClassName, bool bExternalizable, bool bDynamic)
{
	m_bExternalizable = bExternalizable;
	m_bDynamic        = bDynamic;
	m_strClassName	  = strClassName;
}

RTMP_LIB::AMF3ClassDefinition::~AMF3ClassDefinition() {}

void RTMP_LIB::AMF3ClassDefinition::AddProperty(const std::string &strPropertyName)
{
	m_properties.push_back(strPropertyName);
}

const std::string & RTMP_LIB::AMF3ClassDefinition::GetProperty(size_t nIndex) const
{
  if (nIndex >= m_properties.size())
    return strEmpty;

  return m_properties[nIndex];
}

int RTMP_LIB::AMF3ClassDefinition::GetMemberCount() const
{
  return m_properties.size();
}

