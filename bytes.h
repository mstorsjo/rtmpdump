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

#ifndef __BYTES_H__
#define __BYTES_H__

#include <stdint.h>

#ifdef WIN32
// Windows is little endian only
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN    4321
#define __BYTE_ORDER __LITTLE_ENDIAN
#define __FLOAT_WORD_ORDER __BYTE_ORDER

typedef unsigned char uint8_t;

#elif (defined(__FreeBSD__) && __FreeBSD_version >= 470000) || defined(__OpenBSD__) || defined(__NetBSD__) // *BSD
#include <sys/endian.h>
#define __BIG_ENDIAN    BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __BYTE_ORDER    BYTE_ORDER

#elif (defined(BSD) && (BSD >= 199103)) || defined(__MacOSX__) // more BSD
#include <machine/endian.h>
#define __BIG_ENDIAN	BIG_ENDIAN
#define __LITTLE_ENDIAN	LITTLE_ENDIAN
#define __BYTE_ORDER	BYTE_ORDER

#elif defined(__linux__) //|| defined (__BEOS__) // Linux, BeOS
#include <endian.h>
#include <byteswap.h>

//typedef __uint64_t uint64_t;
//typedef __uint32_t uint32_t;
#endif

// define missing byte swap macros
#ifndef __bswap_32
#define __bswap_32(x) \
     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |               \
     (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif

// define default endianness
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN	1234
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN	4321
#endif

#ifndef __BYTE_ORDER
#warning "Byte order not defined on your system, assuming little endian!"
#define __BYTE_ORDER	__LITTLE_ENDIAN
#endif

// ok, we assume to have the same float word order and byte order if float word order is not defined
#ifndef __FLOAT_WORD_ORDER
#warning "Float word order not defined, assuming the same as byte order!"
#define __FLOAT_WORD_ORDER	__BYTE_ORDER
#endif

#if !defined(__BYTE_ORDER) || !defined(__FLOAT_WORD_ORDER)
#error "Undefined byte or float word order!"
#endif

#if __FLOAT_WORD_ORDER != __BIG_ENDIAN && __FLOAT_WORD_ORDER != __LITTLE_ENDIAN
#error "Unknown/unsupported float word order!"
#endif

#if __BYTE_ORDER != __BIG_ENDIAN && __BYTE_ORDER != __LITTLE_ENDIAN
#error "Unknown/unsupported byte order!"
#endif

#endif

