#ifndef __AMF_OBJECT__H__
#define __AMF_OBJECT__H__
/*
 *      Copyright (C) 2005-2008 Team XBMC
 *      http://www.xbmc.org
 *	Copyright (C) 2008-2009 Andrej Stepanchuk
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
#include <vector>
#include <stdint.h>

namespace RTMP_LIB
{
  typedef enum {AMF_INVALID, AMF_NUMBER, AMF_BOOLEAN, AMF_STRING, AMF_OBJECT, AMF_NULL, AMF_MIXEDARRAY, AMF_ARRAY, AMF_DATE } AMFDataType;

  class AMFObjectProperty;
  class AMFObject
  {
    public:
      AMFObject();
      virtual ~AMFObject();

      int Encode(char *pBuffer, int nSize) const;
      int AMF3Decode(const char * pBuffer, int nSize, bool bDecodeName=false);
      int Decode(const char *pBuffer, int nSize, bool bDecodeName=false);
      int DecodeArray(const char * pBuffer, int nSize, int nArrayLen, bool bDecodeName=false);

      void AddProperty(const AMFObjectProperty &prop);

      int GetPropertyCount() const;
      const AMFObjectProperty &GetProperty(const std::string &strName) const;
      const AMFObjectProperty &GetProperty(size_t nIndex) const;

      void Dump() const;
      void Reset();
    protected:
      static AMFObjectProperty m_invalidProp; // returned when no prop matches
      std::vector<AMFObjectProperty> m_properties;
  };

  class AMFObjectProperty
  {
    public:
      AMFObjectProperty();
      AMFObjectProperty(const std::string &strName, double dValue);
      AMFObjectProperty(const std::string &strName, bool   bValue);
      AMFObjectProperty(const std::string &strName, const std::string &strValue);
      AMFObjectProperty(const std::string &strName, const AMFObject &objValue);
     
      virtual ~AMFObjectProperty();

      const std::string &GetPropName() const;
      void SetPropName(const std::string& strName);

      AMFDataType GetType() const;

      bool IsValid() const;

      double GetNumber() const;
      bool   GetBoolean() const;
      const std::string &GetString() const;
      const AMFObject &GetObject() const;

      int Encode(char *pBuffer, int nSize) const;
      int AMF3Decode(const char * pBuffer, int nSize, bool bDecodeName=false);
      int Decode(const char *pBuffer, int nSize, bool bDecodeName);

      void Reset();
      void Dump() const;
    protected:
      int EncodeName(char *pBuffer) const;

      std::string m_strName;

      AMFDataType m_type;
      double      m_dNumVal;
      int16_t	  m_nUTCOffset;
      AMFObject   m_objVal;
      std::string m_strVal;
  };

  class AMF3ClassDefinition
  {
    public:
      AMF3ClassDefinition(const std::string &strClassName, bool bExternalizable, bool bDynamic);
      virtual ~AMF3ClassDefinition();

      void AddProperty(const std::string &strPropertyName);
      const std::string &GetProperty(size_t nIndex) const;

      int GetMemberCount() const;

      bool isExternalizable() { return m_bExternalizable; }
      bool isDynamic() { return m_bDynamic; }
    protected:
      std::string m_strClassName;
      bool	  m_bExternalizable;
      bool 	  m_bDynamic;

      std::vector<std::string> m_properties;
  };
};

#endif
