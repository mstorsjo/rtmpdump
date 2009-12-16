/*
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
#include <assert.h>
#include <stdlib.h>

#include "amf.h"
#include "log.h"
#include "bytes.h"

static const AMFObjectProperty AMFProp_Invalid = { {0, 0}, AMF_INVALID };
static const AVal AV_empty = { 0, 0 };

/* Data is Big-Endian */
unsigned short
AMF_DecodeInt16(const char *data)
{
  unsigned char *c = (unsigned char *) data;
  unsigned short val;
  val = (c[0] << 8) | c[1];
  return val;
}

unsigned int
AMF_DecodeInt24(const char *data)
{
  unsigned char *c = (unsigned char *) data;
  unsigned int val;
  val = (c[0] << 16) | (c[1] << 8) | c[2];
  return val;
}

unsigned int
AMF_DecodeInt32(const char *data)
{
  unsigned char *c = (unsigned char *) data;
  unsigned int val;
  val = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
  return val;
}

void
AMF_DecodeString(const char *data, AVal *bv)
{
  bv->av_len = AMF_DecodeInt16(data);
  bv->av_val = (bv->av_len > 0) ? (char *) data + 2 : NULL;
}

bool
AMF_DecodeBoolean(const char *data)
{
  return *data != 0;
}

int
AMF_EncodeInt16(char *output, short nVal)
{
  output[1] = nVal & 0xff;
  output[0] = nVal >> 8;
  return 2;
}

int
AMF_EncodeInt24(char *output, int nVal)
{
  output[2] = nVal & 0xff;
  output[1] = nVal >> 8;
  output[0] = nVal >> 16;
  return 3;
}

int
AMF_EncodeInt32(char *output, int nVal)
{
  output[3] = nVal & 0xff;
  output[2] = nVal >> 8;
  output[1] = nVal >> 16;
  output[0] = nVal >> 24;
  return 4;
}

int
AMF_EncodeString(char *output, const AVal *bv)
{
  char *buf = output;
  *buf++ = AMF_STRING;

  buf += AMF_EncodeInt16(buf, bv->av_len);

  memcpy(buf, bv->av_val, bv->av_len);
  buf += bv->av_len;

  return buf - output;
}

int
AMF_EncodeNumber(char *output, double dVal)
{
  char *buf = output;
  *buf++ = AMF_NUMBER;		// type: Number

  WriteNumber(buf, dVal);
  buf += 8;

  return 9;
}

int
AMF_EncodeBoolean(char *output, bool bVal)
{
  char *buf = output;

  *buf++ = AMF_BOOLEAN;

  *buf = bVal ? 0x01 : 0x00;

  return 2;
}

void
AMFProp_GetName(AMFObjectProperty *prop, AVal *name)
{
  *name = prop->p_name;
}

void
AMFProp_SetName(AMFObjectProperty *prop, AVal *name)
{
  prop->p_name = *name;
}

AMFDataType
AMFProp_GetType(AMFObjectProperty *prop)
{
  return prop->p_type;
}

double
AMFProp_GetNumber(AMFObjectProperty *prop)
{
  return prop->p_vu.p_number;
}

int
AMFProp_GetBoolean(AMFObjectProperty *prop)
{
  return prop->p_vu.p_number != 0;
}

void
AMFProp_GetString(AMFObjectProperty *prop, AVal *str)
{
  *str = prop->p_vu.p_aval;
}

void
AMFProp_GetObject(AMFObjectProperty *prop, AMFObject *obj)
{
  *obj = prop->p_vu.p_object;
}

int
AMFProp_IsValid(AMFObjectProperty *prop)
{
  return prop->p_type != AMF_INVALID;
}

int
AMFProp_Encode(AMFObjectProperty *prop, char *pBuffer, int nSize)
{
  int nBytes = 0;

  if (prop->p_type == AMF_INVALID)
    return -1;

  if (prop->p_type != AMF_NULL && nSize < prop->p_name.av_len + 2 + 1)
    return -1;

  if (prop->p_type != AMF_NULL && prop->p_name.av_len)
    {
      *pBuffer++ = prop->p_name.av_len >> 8;
      *pBuffer++ = prop->p_name.av_len & 0xff;
      memcpy(pBuffer, prop->p_name.av_val, prop->p_name.av_len);
      pBuffer += prop->p_name.av_len;
      nBytes += prop->p_name.av_len + 2;
      nSize -= nBytes;
    }

  switch (prop->p_type)
    {
    case AMF_NUMBER:
      if (nSize < 9)
	return -1;
      nBytes += AMF_EncodeNumber(pBuffer, prop->p_vu.p_number);
      break;

    case AMF_BOOLEAN:
      if (nSize < 2)
	return -1;
      nBytes += AMF_EncodeBoolean(pBuffer, prop->p_vu.p_number != 0);
      break;

    case AMF_STRING:
      if (nSize < prop->p_vu.p_aval.av_len + (int) sizeof(short))
	return -1;
      nBytes += AMF_EncodeString(pBuffer, &prop->p_vu.p_aval);
      break;

    case AMF_NULL:
      if (nSize < 1)
	return -1;
      *pBuffer = AMF_NULL;
      nBytes += 1;
      break;

    case AMF_OBJECT:
      {
	int nRes = AMF_Encode(&prop->p_vu.p_object, pBuffer, nSize);
	if (nRes == -1)
	  return -1;

	nBytes += nRes;
	break;
      }
    default:
      Log(LOGERROR, "%s, invalid type. %d", __FUNCTION__, prop->p_type);
      return -1;
    };

  return nBytes;
}

#define AMF3_INTEGER_MAX	268435455
#define AMF3_INTEGER_MIN	-268435456

int
AMF3ReadInteger(const char *data, int32_t *valp)
{
  int i = 0;
  int32_t val = 0;

  while (i <= 2)
    {				/* handle first 3 bytes */
      if (data[i] & 0x80)
	{			// byte used
	  val <<= 7;		// shift up
	  val |= (data[i] & 0x7f);	// add bits
	  i++;
	}
      else
	{
	  break;
	}
    }

  if (i > 2)
    {				// use 4th byte, all 8bits
      val <<= 8;
      val |= data[3];

      // range check
      if (val > AMF3_INTEGER_MAX)
	val -= (1 << 29);
    }
  else
    {				// use 7bits of last unparsed byte (0xxxxxxx)
      val <<= 7;
      val |= data[i];
    }

  *valp = val;

  return i > 2 ? 4 : i + 1;
}

int
AMF3ReadString(const char *data, AVal *str)
{
  assert(str != 0);

  int32_t ref = 0;
  int len = AMF3ReadInteger(data, &ref);
  data += len;

  if ((ref & 0x1) == 0)
    {				/* reference: 0xxx */
      uint32_t refIndex = (ref >> 1);
      Log(LOGDEBUG,
	  "%s, string reference, index: %d, not supported, ignoring!",
	  refIndex);
      return len;
    }
  else
    {
      uint32_t nSize = (ref >> 1);

      str->av_val = (char *) data;
      str->av_len = nSize;

      return len + nSize;
    }
  return len;
}

int
AMF3Prop_Decode(AMFObjectProperty *prop, const char *pBuffer, int nSize,
		int bDecodeName)
{
  int nOriginalSize = nSize;
  AMF3DataType type;

  prop->p_name.av_len = 0;
  prop->p_name.av_val = NULL;

  if (nSize == 0 || !pBuffer)
    {
      Log(LOGDEBUG, "empty buffer/no buffer pointer!");
      return -1;
    }

  /* decode name */
  if (bDecodeName)
    {
      AVal name;
      int nRes = AMF3ReadString(pBuffer, &name);

      if (name.av_len <= 0)
	return nRes;

      prop->p_name = name;
      pBuffer += nRes;
      nSize -= nRes;
    }

  /* decode */
  type = *pBuffer++;
  nSize--;

  switch (type)
    {
    case AMF3_UNDEFINED:
    case AMF3_NULL:
      prop->p_type = AMF_NULL;
      break;
    case AMF3_FALSE:
      prop->p_type = AMF_BOOLEAN;
      prop->p_vu.p_number = 0.0;
      break;
    case AMF3_TRUE:
      prop->p_type = AMF_BOOLEAN;
      prop->p_vu.p_number = 1.0;
      break;
    case AMF3_INTEGER:
      {
	int32_t res = 0;
	int len = AMF3ReadInteger(pBuffer, &res);
	prop->p_vu.p_number = (double) res;
	prop->p_type = AMF_NUMBER;
	nSize -= len;
	break;
      }
    case AMF3_DOUBLE:
      if (nSize < 8)
	return -1;
      prop->p_vu.p_number = ReadNumber(pBuffer);
      prop->p_type = AMF_NUMBER;
      nSize -= 8;
      break;
    case AMF3_STRING:
    case AMF3_XML_DOC:
    case AMF3_XML:
      {
	int len = AMF3ReadString(pBuffer, &prop->p_vu.p_aval);
	prop->p_type = AMF_STRING;
	nSize -= len;
	break;
      }
    case AMF3_DATE:
      {
	int32_t res = 0;
	int len = AMF3ReadInteger(pBuffer, &res);

	nSize -= len;
	pBuffer += len;

	if ((res & 0x1) == 0)
	  {			/* reference */
	    uint32_t nIndex = (res >> 1);
	    Log(LOGDEBUG, "AMF3_DATE reference: %d, not supported!", nIndex);
	  }
	else
	  {
	    if (nSize < 8)
	      return -1;

	    prop->p_vu.p_number = ReadNumber(pBuffer);
	    nSize -= 8;
	    prop->p_type = AMF_NUMBER;
	  }
	break;
      }
    case AMF3_OBJECT:
      {
	int nRes = AMF3_Decode(&prop->p_vu.p_object, pBuffer, nSize, true);
	if (nRes == -1)
	  return -1;
	nSize -= nRes;
	prop->p_type = AMF_OBJECT;
	break;
      }
    case AMF3_ARRAY:
    case AMF3_BYTE_ARRAY:
    default:
      Log(LOGDEBUG, "%s - AMF3 unknown/unsupported datatype 0x%02x, @0x%08X",
	  __FUNCTION__, (unsigned char) (*pBuffer), pBuffer);
      return -1;
    }

  return nOriginalSize - nSize;
}

int
AMFProp_Decode(AMFObjectProperty *prop, const char *pBuffer, int nSize,
	       int bDecodeName)
{
  int nOriginalSize = nSize;

  prop->p_name.av_len = 0;
  prop->p_name.av_val = NULL;

  if (nSize == 0 || !pBuffer)
    {
      Log(LOGDEBUG, "%s: Empty buffer/no buffer pointer!", __FUNCTION__);
      return -1;
    }

  if (bDecodeName && nSize < 4)
    {				/* at least name (length + at least 1 byte) and 1 byte of data */
      Log(LOGDEBUG,
	  "%s: Not enough data for decoding with name, less then 4 bytes!",
	  __FUNCTION__);
      return -1;
    }

  if (bDecodeName)
    {
      unsigned short nNameSize = AMF_DecodeInt16(pBuffer);
      if (nNameSize > nSize - 2)
	{
	  Log(LOGDEBUG,
	      "%s: Name size out of range: namesize (%d) > len (%d) - 2",
	      __FUNCTION__, nNameSize, nSize);
	  return -1;
	}

      AMF_DecodeString(pBuffer, &prop->p_name);
      nSize -= 2 + nNameSize;
      pBuffer += 2 + nNameSize;
    }

  if (nSize == 0)
    {
      return -1;
    }

  nSize--;

  prop->p_type = *pBuffer++;
  switch (prop->p_type)
    {
    case AMF_NUMBER:
      if (nSize < 8)
	return -1;
      prop->p_vu.p_number = ReadNumber(pBuffer);
      nSize -= 8;
      break;
    case AMF_BOOLEAN:
      if (nSize < 1)
	return -1;
      prop->p_vu.p_number = (double) AMF_DecodeBoolean(pBuffer);
      nSize--;
      break;
    case AMF_STRING:
      {
	unsigned short nStringSize = AMF_DecodeInt16(pBuffer);

	if (nSize < (long) nStringSize + 2)
	  return -1;
	AMF_DecodeString(pBuffer, &prop->p_vu.p_aval);
	nSize -= (2 + nStringSize);
	break;
      }
    case AMF_OBJECT:
      {
	int nRes = AMF_Decode(&prop->p_vu.p_object, pBuffer, nSize, true);
	if (nRes == -1)
	  return -1;
	nSize -= nRes;
	break;
      }
    case AMF_MOVIECLIP:
      {
	Log(LOGERROR, "AMF_MOVIECLIP reserved!");
	return -1;
	break;
      }
    case AMF_NULL:
    case AMF_UNDEFINED:
    case AMF_UNSUPPORTED:
      prop->p_type = AMF_NULL;
      break;
    case AMF_REFERENCE:
      {
	Log(LOGERROR, "AMF_REFERENCE not supported!");
	return -1;
	break;
      }
    case AMF_ECMA_ARRAY:
      {
	nSize -= 4;

	/* next comes the rest, mixed array has a final 0x000009 mark and names, so its an object */
	int nRes = AMF_Decode(&prop->p_vu.p_object, pBuffer + 4, nSize, true);
	if (nRes == -1)
	  return -1;
	nSize -= nRes;
	prop->p_type = AMF_OBJECT;
	break;
      }
    case AMF_OBJECT_END:
      {
	return -1;
	break;
      }
    case AMF_STRICT_ARRAY:
      {
	unsigned int nArrayLen = AMF_DecodeInt32(pBuffer);
	nSize -= 4;

	int nRes = AMF_DecodeArray(&prop->p_vu.p_object, pBuffer + 4, nSize,
				   nArrayLen, false);
	if (nRes == -1)
	  return -1;
	nSize -= nRes;
	prop->p_type = AMF_OBJECT;
	break;
      }
    case AMF_DATE:
      {
	Log(LOGDEBUG, "AMF_DATE");

	if (nSize < 10)
	  return -1;

	prop->p_vu.p_number = ReadNumber(pBuffer);
	prop->p_UTCoffset = AMF_DecodeInt16(pBuffer + 8);

	nSize -= 10;
	break;
      }
    case AMF_LONG_STRING:
      {
	unsigned int nStringSize = AMF_DecodeInt32(pBuffer);
	if (nSize < (long) nStringSize + 4)
	  return -1;
	AMF_DecodeString(pBuffer, &prop->p_vu.p_aval);
	nSize -= (4 + nStringSize);
	prop->p_type = AMF_STRING;
	break;
      }
    case AMF_RECORDSET:
      {
	Log(LOGERROR, "AMF_RECORDSET reserved!");
	return -1;
	break;
      }
    case AMF_XML_DOC:
      {
	Log(LOGERROR, "AMF_XML_DOC not supported!");
	return -1;
	break;
      }
    case AMF_TYPED_OBJECT:
      {
	Log(LOGERROR, "AMF_TYPED_OBJECT not supported!");
	return -1;
	break;
      }
    case AMF_AVMPLUS:
      {
	int nRes = AMF3_Decode(&prop->p_vu.p_object, pBuffer, nSize, true);
	if (nRes == -1)
	  return -1;
	nSize -= nRes;
	prop->p_type = AMF_OBJECT;
	break;
      }
    default:
      Log(LOGDEBUG, "%s - unknown datatype 0x%02x, @0x%08X", __FUNCTION__,
	  prop->p_type, pBuffer - 1);
      return -1;
    }

  return nOriginalSize - nSize;
}

void
AMFProp_Dump(AMFObjectProperty *prop)
{
  char strRes[256];
  char str[256];
  AVal name;

  if (prop->p_type == AMF_INVALID)
    {
      Log(LOGDEBUG, "Property: INVALID");
      return;
    }

  if (prop->p_type == AMF_NULL)
    {
      Log(LOGDEBUG, "Property: NULL");
      return;
    }

  if (prop->p_name.av_len) {
    name = prop->p_name;
  } else {
    name.av_val = "no-name.";
    name.av_len = sizeof("no-name.")-1;
  }
  if (name.av_len > 25)
    name.av_len = 25;

  snprintf(strRes, 255, "Name: %.*s, ", name.av_len, name.av_val);

  if (prop->p_type == AMF_OBJECT)
    {
      Log(LOGDEBUG, "Property: <%sOBJECT>", strRes);
      AMF_Dump(&prop->p_vu.p_object);
      return;
    }

  switch (prop->p_type)
    {
    case AMF_NUMBER:
      snprintf(str, 255, "NUMBER:\t%.2f", prop->p_vu.p_number);
      break;
    case AMF_BOOLEAN:
      snprintf(str, 255, "BOOLEAN:\t%s",
	       prop->p_vu.p_number != 0.0 ? "TRUE" : "FALSE");
      break;
    case AMF_STRING:
      snprintf(str, 255, "STRING:\t%.*s", prop->p_vu.p_aval.av_len, prop->p_vu.p_aval.av_val);
      break;
    case AMF_DATE:
      snprintf(str, 255, "DATE:\ttimestamp: %.2f, UTC offset: %d",
	       prop->p_vu.p_number, prop->p_UTCoffset);
      break;
    default:
      snprintf(str, 255, "INVALID TYPE 0x%02x", (unsigned char) prop->p_type);
    }

  Log(LOGDEBUG, "Property: <%s%s>", strRes, str);
}

void
AMFProp_Reset(AMFObjectProperty *prop)
{
  if (prop->p_type == AMF_OBJECT)
    AMF_Reset(&prop->p_vu.p_object);
  else
    {
      prop->p_vu.p_aval.av_len = 0;
      prop->p_vu.p_aval.av_val = NULL;
    }
  prop->p_type = AMF_INVALID;
}

/* AMFObject */

int
AMF_Encode(AMFObject *obj, char *pBuffer, int nSize)
{
  int nOriginalSize = nSize;
  int i;

  if (nSize < 4)
    return -1;

  *pBuffer = AMF_OBJECT;

  for (i = 0; i < obj->o_num; i++)
    {
      int nRes = AMFProp_Encode(&obj->o_props[i], pBuffer, nSize);
      if (nRes == -1)
	{
	  Log(LOGERROR, "AMF_Encode - failed to encode property in index %d",
	      i);
	}
      else
	{
	  nSize -= nRes;
	  pBuffer += nRes;
	}
    }

  if (nSize < 3)
    return -1;			// no room for the end marker

  AMF_EncodeInt24(pBuffer, AMF_OBJECT_END);
  nSize -= 3;

  return nOriginalSize - nSize;
}

int
AMF_DecodeArray(AMFObject *obj, const char *pBuffer, int nSize,
		int nArrayLen, bool bDecodeName)
{
  int nOriginalSize = nSize;
  bool bError = false;

  obj->o_num = 0;
  obj->o_props = NULL;
  while (nArrayLen > 0)
    {
      nArrayLen--;

      AMFObjectProperty prop;
      int nRes = AMFProp_Decode(&prop, pBuffer, nSize, bDecodeName);
      if (nRes == -1)
	bError = true;
      else
	{
	  nSize -= nRes;
	  pBuffer += nRes;
	  AMF_AddProp(obj, &prop);
	}
    }
  if (bError)
    return -1;

  return nOriginalSize - nSize;
}

int
AMF3_Decode(AMFObject *obj, const char *pBuffer, int nSize, bool bAMFData)
{
  int nOriginalSize = nSize;
  int32_t ref;
  int len;

  obj->o_num = 0;
  obj->o_props = NULL;
  if (bAMFData)
    {
      if (*pBuffer != AMF3_OBJECT)
	Log(LOGERROR,
	    "AMF3 Object encapsulated in AMF stream does not start with AMF3_OBJECT!");
      pBuffer++;
      nSize--;
    }

  ref = 0;
  len = AMF3ReadInteger(pBuffer, &ref);
  pBuffer += len;
  nSize -= len;

  if ((ref & 1) == 0)
    {				/* object reference, 0xxx */
      uint32_t objectIndex = (ref >> 1);

      Log(LOGDEBUG, "Object reference, index: %d", objectIndex);
    }
  else				/* object instance */
    {
      int32_t classRef = (ref >> 1);

      AMF3ClassDef cd = { {0, 0}
      };
      AMFObjectProperty prop;

      if ((classRef & 0x1) == 0)
	{			/* class reference */
	  uint32_t classIndex = (classRef >> 1);
	  Log(LOGDEBUG, "Class reference: %d", classIndex);
	}
      else
	{
	  int32_t classExtRef = (classRef >> 1);
	  int i;

	  cd.cd_externalizable = (classExtRef & 0x1) == 1;
	  cd.cd_dynamic = ((classExtRef >> 1) & 0x1) == 1;

	  cd.cd_num = classExtRef >> 2;

	  // class name

	  len = AMF3ReadString(pBuffer, &cd.cd_name);
	  nSize -= len;
	  pBuffer += len;

	  //std::string str = className;

	  Log(LOGDEBUG,
	      "Class name: %s, externalizable: %d, dynamic: %d, classMembers: %d",
	      cd.cd_name.av_val, cd.cd_externalizable, cd.cd_dynamic,
	      cd.cd_num);

	  for (i = 0; i < cd.cd_num; i++)
	    {
	      AVal memberName;
	      len = AMF3ReadString(pBuffer, &memberName);
	      Log(LOGDEBUG, "Member: %s", memberName.av_val);
	      AMF3CD_AddProp(&cd, &memberName);
	      nSize -= len;
	      pBuffer += len;
	    }
	}

      /* add as referencable object */

      if (cd.cd_externalizable)
	{
	  int nRes;
	  AVal name = AVC("DEFAULT_ATTRIBUTE");

	  Log(LOGDEBUG, "Externalizable, TODO check");

	  nRes = AMF3Prop_Decode(&prop, pBuffer, nSize, false);
	  if (nRes == -1)
	    Log(LOGDEBUG, "%s, failed to decode AMF3 property!",
		__FUNCTION__);
	  else
	    {
	      nSize -= nRes;
	      pBuffer += nRes;
	    }

	  AMFProp_SetName(&prop, &name);
	  AMF_AddProp(obj, &prop);
	}
      else
	{
	  int nRes, i;
	  for (i = 0; i < cd.cd_num; i++)	/* non-dynamic */
	    {
	      nRes = AMF3Prop_Decode(&prop, pBuffer, nSize, false);
	      if (nRes == -1)
		Log(LOGDEBUG, "%s, failed to decode AMF3 property!",
		    __FUNCTION__);

	      AMFProp_SetName(&prop, AMF3CD_GetProp(&cd, i));
	      AMF_AddProp(obj, &prop);

	      pBuffer += nRes;
	      nSize -= nRes;
	    }
	  if (cd.cd_dynamic)
	    {
	      int len = 0;

	      do
		{
		  nRes = AMF3Prop_Decode(&prop, pBuffer, nSize, true);
		  AMF_AddProp(obj, &prop);

		  pBuffer += nRes;
		  nSize -= nRes;

		  len = prop.p_name.av_len;
		}
	      while (len > 0);
	    }
	}
      Log(LOGDEBUG, "class object!");
    }
  return nOriginalSize - nSize;
}

int
AMF_Decode(AMFObject *obj, const char *pBuffer, int nSize, bool bDecodeName)
{
  int nOriginalSize = nSize;
  bool bError = false;		/* if there is an error while decoding - try to at least find the end mark AMF_OBJECT_END */

  obj->o_num = 0;
  obj->o_props = NULL;
  while (nSize >= 3)
    {
      AMFObjectProperty prop;
      int nRes;

      if (AMF_DecodeInt24(pBuffer) == AMF_OBJECT_END)
	{
	  nSize -= 3;
	  bError = false;
	  break;
	}

      if (bError)
	{
	  Log(LOGERROR,
	      "DECODING ERROR, IGNORING BYTES UNTIL NEXT KNOWN PATTERN!");
	  nSize--;
	  pBuffer++;
	  continue;
	}

      nRes = AMFProp_Decode(&prop, pBuffer, nSize, bDecodeName);
      if (nRes == -1)
	bError = true;
      else
	{
	  nSize -= nRes;
	  pBuffer += nRes;
	  AMF_AddProp(obj, &prop);
	}
    }

  if (bError)
    return -1;

  return nOriginalSize - nSize;
}

void
AMF_AddProp(AMFObject *obj, const AMFObjectProperty *prop)
{
  if (!(obj->o_num & 0x0f))
    obj->o_props =
      realloc(obj->o_props, (obj->o_num + 16) * sizeof(AMFObjectProperty));
  obj->o_props[obj->o_num++] = *prop;
}

int
AMF_CountProp(AMFObject *obj)
{
  return obj->o_num;
}

AMFObjectProperty *
AMF_GetProp(AMFObject *obj, const AVal *name, int nIndex)
{
  if (nIndex >= 0)
    {
      if (nIndex <= obj->o_num)
	return &obj->o_props[nIndex];
    }
  else
    {
      int n;
      for (n = 0; n < obj->o_num; n++)
	{
	  if (AVMATCH(&obj->o_props[n].p_name, name))
	    return &obj->o_props[n];
	}
    }

  return (AMFObjectProperty *) & AMFProp_Invalid;
}

void
AMF_Dump(AMFObject *obj)
{
  int n;
  for (n = 0; n < obj->o_num; n++)
    {
      AMFProp_Dump(&obj->o_props[n]);
    }
}

void
AMF_Reset(AMFObject *obj)
{
  int n;
  for (n = 0; n < obj->o_num; n++)
    {
      AMFProp_Reset(&obj->o_props[n]);
    }
  free(obj->o_props);
  obj->o_props = NULL;
  obj->o_num = 0;
}


/* AMF3ClassDefinition */

void
AMF3CD_AddProp(AMF3ClassDef *cd, AVal *prop)
{
  if (!(cd->cd_num & 0x0f))
    cd->cd_props = realloc(cd->cd_props, (cd->cd_num + 16) * sizeof(AVal));
  cd->cd_props[cd->cd_num++] = *prop;
}

AVal *
AMF3CD_GetProp(AMF3ClassDef *cd, int nIndex)
{
  if (nIndex >= cd->cd_num)
    return (AVal *)&AV_empty;
  return &cd->cd_props[nIndex];
}
