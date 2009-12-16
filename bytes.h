#ifndef __BYTES_H__
#define __BYTES_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
// Windows is little endian only 
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN    4321
#define __BYTE_ORDER __LITTLE_ENDIAN
#define __FLOAT_WORD_ORDER __BYTE_ORDER

typedef unsigned char uint8_t;
/*typedef signed char int8_t;
typedef signed short int16_t;
typedef signed long int int32_t;
typedef signed long long int int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long int uint32_t;
typedef unsigned long long int uint64_t;
*/

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

#ifndef __bswap_64
#define __bswap_64(x) \
     ((((x) & 0xff00000000000000ull) >> 56)                                   \
      | (((x) & 0x00ff000000000000ull) >> 40)                                 \
      | (((x) & 0x0000ff0000000000ull) >> 24)                                 \
      | (((x) & 0x000000ff00000000ull) >> 8)                                  \
      | (((x) & 0x00000000ff000000ull) << 8)                                  \
      | (((x) & 0x0000000000ff0000ull) << 24)                                 \
      | (((x) & 0x000000000000ff00ull) << 40)                                 \
      | (((x) & 0x00000000000000ffull) << 56))
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

void WriteNumber(char *data, double dVal);
double ReadNumber(const char *data);

int ReadInt32LE(const char *data);
int EncodeInt32LE(char *output, int nVal);

#ifdef __cplusplus
}
#endif

#endif

